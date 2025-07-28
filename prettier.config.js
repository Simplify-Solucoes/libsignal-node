module.exports = {
  // Basic formatting options
  semi: true,
  trailingComma: 'all',
  singleQuote: true,
  printWidth: 100,
  tabWidth: 2,
  useTabs: false,
  
  // JavaScript/TypeScript specific
  arrowParens: 'avoid',
  bracketSpacing: true,
  bracketSameLine: false,
  quoteProps: 'as-needed',
  
  // File-specific overrides
  overrides: [
    {
      files: '*.{js,ts}',
      options: {
        parser: 'typescript',
      },
    },
    {
      files: '*.json',
      options: {
        parser: 'json',
        printWidth: 80,
      },
    },
    {
      files: '*.md',
      options: {
        parser: 'markdown',
        printWidth: 80,
        proseWrap: 'always',
      },
    },
  ],
};