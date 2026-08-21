# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Which source addresses may use a credential.

Two properties matter most and are easy to get backwards: an unconfigured list
allows everything (the control is opt-in, so shipping it cannot lock out
existing credentials), while a configured list denies anything it does not
recognise, including an address that could not be determined.
"""

import pytest

from security.ip_allowlist import is_allowed, normalize_entries


class TestNormalizeEntries:

    def test_a_bare_address_becomes_a_single_host_network(self):
        assert normalize_entries(["10.0.0.1"]) == ["10.0.0.1/32"]

    def test_a_bare_ipv6_address_becomes_a_single_host_network(self):
        assert normalize_entries(["2001:db8::1"]) == ["2001:db8::1/128"]

    def test_a_cidr_block_is_kept(self):
        assert normalize_entries(["10.0.0.0/8"]) == ["10.0.0.0/8"]

    def test_a_host_address_with_a_prefix_is_read_as_its_network(self):
        assert normalize_entries(["10.0.0.5/24"]) == ["10.0.0.0/24"]

    def test_blank_entries_are_dropped(self):
        assert normalize_entries(["10.0.0.1", "", "   "]) == ["10.0.0.1/32"]

    def test_none_and_empty_produce_an_empty_list(self):
        assert normalize_entries(None) == []
        assert normalize_entries([])   == []

    @pytest.mark.parametrize("bad", ["not-an-ip", "10.0.0.300", "10.0.0.0/99", "::/999"])
    def test_a_typo_is_rejected_at_configuration_time(self, bad):
        """Rejecting on write beats silently widening or narrowing access later."""
        with pytest.raises(ValueError):
            normalize_entries([bad])


class TestIsAllowed:

    def test_an_unconfigured_list_allows_everything(self):
        """
        The control is opt-in. Reading "no list" as "deny all" would reject every
        existing credential the moment the column ships.
        """
        assert is_allowed("203.0.113.9", None) is True
        assert is_allowed("203.0.113.9", [])   is True

    def test_an_address_inside_a_configured_network_is_allowed(self):
        assert is_allowed("10.0.0.7", ["10.0.0.0/24"]) is True

    def test_an_address_outside_every_configured_network_is_denied(self):
        assert is_allowed("10.0.1.7", ["10.0.0.0/24"]) is False

    def test_an_exact_host_entry_matches_only_that_host(self):
        assert is_allowed("10.0.0.1", ["10.0.0.1/32"]) is True
        assert is_allowed("10.0.0.2", ["10.0.0.1/32"]) is False

    def test_any_one_entry_is_enough(self):
        entries = ["192.0.2.0/24", "10.0.0.0/8", "203.0.113.5/32"]
        assert is_allowed("10.1.2.3", entries) is True

    def test_ipv6_matching(self):
        assert is_allowed("2001:db8::5", ["2001:db8::/32"]) is True
        assert is_allowed("2001:dead::5", ["2001:db8::/32"]) is False

    def test_the_two_families_can_be_mixed_on_one_credential(self):
        entries = ["10.0.0.0/8", "2001:db8::/32"]
        assert is_allowed("10.1.1.1",    entries) is True
        assert is_allowed("2001:db8::9", entries) is True
        assert is_allowed("192.0.2.1",   entries) is False

    def test_an_address_never_matches_a_network_of_the_other_family(self):
        """Comparing across families raises, so the family is checked first."""
        assert is_allowed("10.0.0.1",    ["2001:db8::/32"]) is False
        assert is_allowed("2001:db8::1", ["10.0.0.0/8"])    is False

    def test_an_undeterminable_address_is_denied_when_a_list_is_configured(self):
        """
        Fail closed. Once an operator has said where a credential may be used, an
        address that cannot be established is not one of those places.
        """
        assert is_allowed(None, ["10.0.0.0/8"]) is False
        assert is_allowed("",   ["10.0.0.0/8"]) is False

    def test_an_unparseable_address_is_denied_when_a_list_is_configured(self):
        assert is_allowed("not-an-ip", ["10.0.0.0/8"]) is False

    def test_one_bad_stored_entry_does_not_void_the_rest(self):
        """
        Entries are validated on write, so a bad row means data that predates
        validation. It must not lock the credential out of its valid networks.
        """
        assert is_allowed("10.0.0.1", ["garbage", "10.0.0.0/8"]) is True

    def test_a_list_of_only_bad_entries_denies(self):
        assert is_allowed("10.0.0.1", ["garbage", "also-garbage"]) is False

    def test_surrounding_whitespace_is_tolerated(self):
        assert is_allowed(" 10.0.0.7 ", ["10.0.0.0/24"]) is True


class TestZeroPrefixRejection:
    """
    A credential that looks restricted but is not is worse than one that is
    openly unrestricted, so a network covering every address is refused.
    """

    @pytest.mark.parametrize("everything", ["0.0.0.0/0", "::/0"])
    def test_a_network_covering_everything_is_refused(self, everything):
        with pytest.raises(ValueError, match="not a restriction"):
            normalize_entries([everything])

    def test_it_is_refused_even_alongside_real_entries(self):
        with pytest.raises(ValueError, match="not a restriction"):
            normalize_entries(["10.0.0.0/8", "0.0.0.0/0"])

    def test_a_narrow_network_is_still_accepted(self):
        assert normalize_entries(["0.0.0.0/8"]) == ["0.0.0.0/8"]


class TestIpv4MappedIpv6:
    """
    An IPv4 address wearing IPv6 clothing is the same address.

    uvicorn on a dual-stack socket reports an IPv4 client as
    `::ffff:203.0.113.5`. Compared naively that is a different family from an
    entry of `203.0.113.5/32`, so it never matches: the operator allowlists
    their own address, is locked out, and the denial log shows the address they
    believe they permitted. A lockout is the expensive direction of this
    control, and this is the shape that causes one without anybody typing
    anything wrong.
    """

    @pytest.mark.parametrize("client,entry", [
        ("::ffff:203.0.113.5", "203.0.113.5/32"),
        ("::ffff:203.0.113.5", "203.0.113.0/24"),
        ("::ffff:10.1.2.3",    "10.0.0.0/8"),
        ("::FFFF:10.1.2.3",    "10.0.0.0/8"),      # the form is case-insensitive
    ])
    def test_a_mapped_client_matches_an_ipv4_entry(self, client, entry):
        assert is_allowed(client, [entry]) is True

    def test_a_plain_client_matches_an_entry_stored_mapped(self):
        """
        The other direction. Unmapping only the client would move the mismatch
        rather than remove it.
        """
        assert is_allowed("203.0.113.5", ["::ffff:203.0.113.5/128"]) is True

    @pytest.mark.parametrize("client,entry", [
        ("::ffff:198.51.100.7", "203.0.113.0/24"),   # outside the network
        ("2001:db8::1",         "203.0.113.0/24"),   # genuinely a different family
        ("::ffff:203.0.113.5",  "2001:db8::/32"),
    ])
    def test_it_still_denies_what_it_should(self, client, entry):
        """The unmapping must not turn a denial into an allow."""
        assert is_allowed(client, [entry]) is False

    def test_real_ipv6_is_unaffected(self):
        assert is_allowed("2001:db8::1", ["2001:db8::/32"]) is True
        assert is_allowed("2001:db9::1", ["2001:db8::/32"]) is False

    def test_a_mapped_entry_is_stored_in_its_ipv4_form(self):
        """
        Canonicalised on write, so what is stored is one thing rather than two
        spellings of it.
        """
        assert normalize_entries(["::ffff:203.0.113.5"])     == ["203.0.113.5/32"]
        assert normalize_entries(["::ffff:203.0.113.0/120"]) == ["203.0.113.0/24"]

    def test_a_prefix_outside_the_mapped_range_is_left_alone(self):
        """
        `::/64` spans far more than the mapped range, so treating it as an IPv4
        network would silently widen what the operator wrote. Only prefixes
        inside `::ffff:0:0/96` are converted.
        """
        assert normalize_entries(["::/64"]) == ["::/64"]
        assert normalize_entries(["2001:db8::/32"]) == ["2001:db8::/32"]

    @pytest.mark.parametrize("everything", ["::ffff:0:0/96", "::ffff:0.0.0.0/96"])
    def test_the_mapped_spelling_of_allow_everything_is_refused(self, everything):
        """
        `::ffff:0:0/96` is a 96-bit prefix as written and `0.0.0.0/0` once
        unmapped. Validating the written form and storing the unmapped one lets
        a restriction that restricts nothing in through the one door the
        zero-prefix check exists to close, so the unmapping happens first and
        the check sees what will actually be stored.
        """
        with pytest.raises(ValueError, match="allows every address"):
            normalize_entries([everything])
