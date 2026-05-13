export type Comment = {
  id: number;
  author: string;
  body: string;
  createdAt: string;
};

const store: Comment[] = [
  {
    id: 1,
    author: "alice",
    body: "First!",
    createdAt: "2026-01-01T00:00:00Z",
  },
  {
    id: 2,
    author: "bob",
    body: "Looks <b>great</b>!",
    createdAt: "2026-01-02T00:00:00Z",
  },
];

let nextId = store.length + 1;

export function listComments(): Comment[] {
  return store.slice();
}

export function addComment(author: string, body: string): Comment {
  const c: Comment = {
    id: nextId++,
    author,
    body,
    createdAt: new Date().toISOString(),
  };
  store.push(c);
  return c;
}

export function deleteComment(id: number): boolean {
  const idx = store.findIndex((c) => c.id === id);
  if (idx === -1) return false;
  store.splice(idx, 1);
  return true;
}
