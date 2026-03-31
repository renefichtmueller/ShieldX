'use client'

import React, { useMemo, useState, useCallback } from 'react'
import { theme } from '../theme'

export interface DataTableColumn<T> {
  readonly key: string
  readonly header: string
  readonly sortable?: boolean
  readonly render?: (row: T) => React.ReactNode
  readonly accessor?: (row: T) => string | number
}

export interface DataTableProps<T> {
  readonly columns: readonly DataTableColumn<T>[]
  readonly data: readonly T[]
  readonly pageSize?: number
  readonly filterable?: boolean
  readonly filterPlaceholder?: string
  readonly getRowKey?: (row: T, index: number) => string
  readonly onRowClick?: (row: T) => void
  readonly className?: string
}

type SortDir = 'asc' | 'desc'

const thStyle: React.CSSProperties = {
  textAlign: 'left',
  padding: '10px 12px',
  fontSize: 11,
  fontWeight: 600,
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  color: theme.colors.textMuted,
  borderBottom: `1px solid ${theme.colors.cardBorder}`,
  cursor: 'pointer',
  userSelect: 'none',
  whiteSpace: 'nowrap',
}

const tdStyle: React.CSSProperties = {
  padding: '10px 12px',
  borderBottom: `1px solid rgba(51, 65, 85, 0.5)`,
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  maxWidth: 300,
}

const btnStyle: React.CSSProperties = {
  padding: '4px 10px',
  border: `1px solid ${theme.colors.cardBorder}`,
  borderRadius: 4,
  background: 'transparent',
  color: theme.colors.text,
  cursor: 'pointer',
  fontSize: 12,
  fontFamily: theme.font,
}

export function DataTable<T>({
  columns,
  data,
  pageSize = 15,
  filterable = false,
  filterPlaceholder = 'Filter\u2026',
  getRowKey,
  onRowClick,
  className,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const [page, setPage] = useState(0)
  const [filter, setFilter] = useState('')

  const handleSort = useCallback(
    (key: string) => {
      if (sortKey === key) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
      } else {
        setSortKey(key)
        setSortDir('asc')
      }
      setPage(0)
    },
    [sortKey]
  )

  const filtered = useMemo(() => {
    if (!filter) return data
    const q = filter.toLowerCase()
    return data.filter((row) =>
      columns.some((col) => {
        const val = col.accessor ? col.accessor(row) : (row as Record<string, unknown>)[col.key]
        return String(val ?? '').toLowerCase().includes(q)
      })
    )
  }, [data, filter, columns])

  const sorted = useMemo(() => {
    if (!sortKey) return filtered
    const col = columns.find((c) => c.key === sortKey)
    if (!col) return filtered
    return [...filtered].sort((a, b) => {
      const aVal = col.accessor ? col.accessor(a) : (a as Record<string, unknown>)[col.key]
      const bVal = col.accessor ? col.accessor(b) : (b as Record<string, unknown>)[col.key]
      const cmp = String(aVal ?? '').localeCompare(String(bVal ?? ''), undefined, { numeric: true })
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [filtered, sortKey, sortDir, columns])

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize))
  const pageData = sorted.slice(page * pageSize, (page + 1) * pageSize)

  return (
    <div className={className} style={{ width: '100%', overflowX: 'auto' }}>
      {filterable ? (
        <div style={{ marginBottom: 12 }}>
          <input
            type="text"
            placeholder={filterPlaceholder}
            value={filter}
            onChange={(e) => { setFilter(e.target.value); setPage(0) }}
            style={{
              width: '100%',
              maxWidth: 300,
              padding: '6px 10px',
              border: `1px solid ${theme.colors.cardBorder}`,
              borderRadius: 4,
              background: theme.colors.bg,
              color: theme.colors.text,
              fontSize: 13,
              fontFamily: theme.font,
              outline: 'none',
            }}
          />
        </div>
      ) : null}
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, fontFamily: theme.font, color: theme.colors.text }}>
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                style={thStyle}
                onClick={col.sortable !== false ? () => handleSort(col.key) : undefined}
              >
                {col.header}
                {sortKey === col.key ? (
                  <span style={{ marginLeft: 4, fontSize: 10 }}>
                    {sortDir === 'asc' ? '\u25B2' : '\u25BC'}
                  </span>
                ) : null}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {pageData.length === 0 ? (
            <tr>
              <td colSpan={columns.length} style={{ ...tdStyle, textAlign: 'center', color: theme.colors.textDim, padding: '32px 12px' }}>
                No data available
              </td>
            </tr>
          ) : (
            pageData.map((row, idx) => (
              <tr
                key={getRowKey ? getRowKey(row, idx) : idx}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                style={onRowClick ? { cursor: 'pointer' } : undefined}
              >
                {columns.map((col) => (
                  <td key={col.key} style={tdStyle}>
                    {col.render
                      ? col.render(row)
                      : String((row as Record<string, unknown>)[col.key] ?? '')}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
      {totalPages > 1 ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 12, fontSize: 12, color: theme.colors.textMuted }}>
          <span>
            Showing {page * pageSize + 1}-{Math.min((page + 1) * pageSize, sorted.length)} of {sorted.length}
          </span>
          <div style={{ display: 'flex', gap: 6 }}>
            <button style={btnStyle} disabled={page === 0} onClick={() => setPage(0)}>First</button>
            <button style={btnStyle} disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Prev</button>
            <button style={btnStyle} disabled={page >= totalPages - 1} onClick={() => setPage((p) => p + 1)}>Next</button>
            <button style={btnStyle} disabled={page >= totalPages - 1} onClick={() => setPage(totalPages - 1)}>Last</button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
