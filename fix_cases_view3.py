with open('src/components/CasesView.tsx', 'r') as f:
    content = f.read()

tag_section = """              {/* Tags Section */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-semibold text-slate-200 flex items-center gap-1.5">
                    <Tag className="w-4 h-4 text-purple-400" />
                    Case Tags
                  </h4>
                </div>
                <div className="flex flex-wrap gap-2 mb-3">
                  {(selectedCaseDetail.tags || []).length === 0 ? (
                    <span className="text-slate-500 italic text-[11px]">No tags assigned.</span>
                  ) : (
                    (selectedCaseDetail.tags || []).map((tag: string, idx: number) => (
                      <span key={idx} className="px-2 py-1 bg-slate-800 text-slate-200 rounded-md border border-slate-700 flex items-center gap-1 text-[11px]">
                        {tag}
                        <button 
                          onClick={() => handleRemoveTag(tag)}
                          disabled={isUpdatingTag}
                          className="text-slate-400 hover:text-red-400 focus:outline-none disabled:opacity-50"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    ))
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={newTag}
                    onChange={(e) => setNewTag(e.target.value)}
                    onKeyDown={handleAddTag}
                    placeholder="Add a tag and press Enter... (e.g. Phishing, Spam)"
                    className="flex-1 bg-slate-900 border border-slate-700 rounded-md px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
                    disabled={isUpdatingTag}
                  />
                </div>
              </div>

              {/* Analyst Notes */}"""

content = content.replace('              {/* Analyst Notes */}', tag_section)

with open('src/components/CasesView.tsx', 'w') as f:
    f.write(content)
