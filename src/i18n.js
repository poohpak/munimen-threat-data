// The public CLI shares validation messages, not the extension's UI catalog.
export const tr = (message, values = []) => message.replace(/\$(\d+)/g,
  (match, index) => values[Number(index) - 1] ?? match);
