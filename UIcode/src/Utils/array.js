export const intersection = (arr1, arr2) =>
  arr1.filter((x) => arr2.includes(x));

export const map = (fn) => (item) => fn(item);
