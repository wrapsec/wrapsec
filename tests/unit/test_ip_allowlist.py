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
