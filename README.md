# SeaWhisper0's Blog

> Writeups & research from the **SeaWhisper0** CTF team.

---

## ✍️ How to add a writeup or research article

**Getting started:**

- **Fork** this repository.
- **Clone** your fork to your local machine.
- Make your changes by following the steps below.
- **Commit and push** to your fork.
- Open a **pull request** to this repository.

### 1️⃣ Register the post in [`/posts/index.txt`](/posts/index.txt)

Add an entry to the JSON array — set **`category`** to `ctf` or `research`:

```json
{
    "title": "Name CTF competition - Name challenge",
    "category": "ctf",
    "file": "posts/ctf/demo.md",
    "date": "2026-01-01",
    "description": "Short one-line summary.",
    "tags": ["reverse", "web", "crypto"]
}
```

| Field | Meaning |
|-------|---------|
| `title` | Post title shown on the card |
| `category` | `ctf` or `research` |
| `file` | Path to the Markdown file |
| `date` | Publish date, `YYYY-MM-DD` |
| `description` | One-line summary on the card |
| `tags` | Topic tags (list) |

### 2️⃣ Write the article in [`/posts`](/posts)

Create your Markdown file (e.g. `/posts/ctf/demo.md`):

````markdown
# Title
**Author**: The name of the person who wrote this article

## Overview
Brief description of the challenge.

## Analysis
What we found and how we approached it.

## Solution
```python
# exploit code here
```
````

- **Images** → put them in the [`/images`](/images) folder, then reference them in the Markdown.
- **Videos** → put them in the [`/videos`](/videos) folder, then reference them in the Markdown.

### 3️⃣ Result

![index](/images/README/index.png)

![web_index](/images/README/web_index.png)

![web_content](/images/README/web_content.png)

---

## 🧭 On-page navigation (Table of Contents)

Each post automatically builds a clickable **"On this page"** sidebar from your Markdown headings. Clicking an entry smooth-scrolls to that section, and the current section is highlighted as you scroll.

**Writing guidelines:**
- Use `#` to `####` headings (`h1`–`h4`). Headings deeper than `####` are not listed.
- Indentation follows heading depth: the shallowest heading in the post sits flush-left, and each extra `#` indents one more level. So a post using only `##`/`###` aligns the `##` items to the left edge.
- Keep the hierarchy consistent (don't jump from `#` straight to `####`) for readable indentation.
- The sidebar only appears when a post has **2 or more headings**; long heading titles wrap onto multiple lines instead of being cut off.

```markdown
# Title
## Overview
## Analysis
### Static analysis
## Solution
```

---

## ⚠️ Notice

- The **code block** supports syntax highlighting for these languages: `c` (C/C++), `python`, `javascript`, `bash`, `markup` (HTML/XML), `nasm` (asm), and `json`.
- If a language other than those listed above is used, `c` is applied by default.

````markdown
```nasm
    mov  rax, 0x1
```
````
