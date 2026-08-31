with open('src/components/CasesView.tsx', 'r') as f:
    content = f.read()

import re

# Add state for tag input
content = content.replace(
    'const [notesDraft, setNotesDraft] = useState(\'\');',
    'const [notesDraft, setNotesDraft] = useState(\'\');\n  const [newTag, setNewTag] = useState(\'\');\n  const [isUpdatingTag, setIsUpdatingTag] = useState(false);'
)

# Add handleAddTag and handleRemoveTag
functions = """  const handleAddTag = async (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && newTag.trim() && selectedCaseDetail) {
      e.preventDefault();
      setIsUpdatingTag(true);
      try {
        const currentTags = selectedCaseDetail.tags || [];
        if (!currentTags.includes(newTag.trim())) {
          const updatedTags = [...currentTags, newTag.trim()];
          const updated = await forensicApi.updateCase(selectedCaseDetail.id, { tags: updatedTags });
          setSelectedCaseDetail((prev: any) => ({ ...prev, tags: updatedTags }));
          setCases(prev => prev.map(c => (c.id === selectedCaseDetail.id ? { ...c, tags: updatedTags } : c)));
        }
        setNewTag('');
      } catch (err) {
        console.warn('Fallback saving tags locally:', err);
      } finally {
        setIsUpdatingTag(false);
      }
    }
  };

  const handleRemoveTag = async (tagToRemove: string) => {
    if (!selectedCaseDetail) return;
    setIsUpdatingTag(true);
    try {
      const currentTags = selectedCaseDetail.tags || [];
      const updatedTags = currentTags.filter((t: string) => t !== tagToRemove);
      const updated = await forensicApi.updateCase(selectedCaseDetail.id, { tags: updatedTags });
      setSelectedCaseDetail((prev: any) => ({ ...prev, tags: updatedTags }));
      setCases(prev => prev.map(c => (c.id === selectedCaseDetail.id ? { ...c, tags: updatedTags } : c)));
    } catch (err) {
      console.warn('Fallback removing tags locally:', err);
    } finally {
      setIsUpdatingTag(false);
    }
  };

  const handleSaveNotes = async () => {"""
content = content.replace('  const handleSaveNotes = async () => {', functions)


with open('src/components/CasesView.tsx', 'w') as f:
    f.write(content)
