import { Button } from "@/components/ui/Button"
import { ApiKey } from "@/lib/types"
import { formatTimestamp, timeAgo } from "@/lib/utils"

interface ApiKeyTableProps {
  keys:     ApiKey[]
  onRevoke: (keyId: string) => void
  revoking: string | null
}

export function ApiKeyTable({ keys, onRevoke, revoking }: ApiKeyTableProps) {
  if (keys.length === 0) {
    return (
      <p className="text-sm text-slate-400 py-4">No API keys created yet.</p>
    )
  }

  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="border-b border-slate-100">
          {["Name", "Key ID", "Created", "Last Used", ""].map((h) => (
            <th key={h} className="text-left pb-2.5 text-xs font-medium text-slate-500 uppercase tracking-wide">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {keys.map((key) => (
          <tr key={key.key_id} className="border-b border-slate-50">
            <td className="py-3 text-sm font-medium text-slate-900">
              {key.name}
            </td>
            <td className="py-3 font-mono text-xs text-slate-500">
              {key.key_id}
            </td>
            <td className="py-3 text-xs text-slate-500">
              {formatTimestamp(key.created_at)}
            </td>
            <td className="py-3 text-xs text-slate-400">
              {key.last_used_at ? timeAgo(key.last_used_at) : "Never"}
            </td>
            <td className="py-3 text-right">
              <Button
                variant="danger"
                size="sm"
                loading={revoking === key.key_id}
                onClick={() => onRevoke(key.key_id)}
              >
                Revoke
              </Button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}