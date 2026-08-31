with open('src/components/CasesView.tsx', 'r') as f:
    content = f.read()

replacement = """                      <td className="py-3.5 px-4 max-w-md">
                        <div className="font-semibold text-slate-200 truncate">{title}</div>
                        <div className="text-[11px] text-slate-400 truncate mt-0.5">{desc}</div>
                        {c.tags && c.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {c.tags.map((tag: string, idx: number) => (
                              <span key={idx} className="px-1.5 py-0.5 bg-slate-800 text-slate-300 rounded text-[9px] border border-slate-700 flex items-center gap-1">
                                <Tag className="w-2 h-2 text-slate-400" />
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>"""

content = content.replace(
    '                      <td className="py-3.5 px-4 max-w-md">\n                        <div className="font-semibold text-slate-200 truncate">{title}</div>\n                        <div className="text-[11px] text-slate-400 truncate mt-0.5">{desc}</div>\n                      </td>',
    replacement
)

with open('src/components/CasesView.tsx', 'w') as f:
    f.write(content)
