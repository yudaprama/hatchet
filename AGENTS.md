# AGENTS

## Code Comments

- Comments should explain non-obvious intent, invariants, or constraints in the current code. Do not mention the old implementation/state (for example, "preserve the behavior of the original query"); state the current rule directly.

## Docs MDX

- In MDX JSX component bodies, such as `<Callout>`, avoid Markdown link syntax (`[text](href)`). Prettier can wrap the label across lines and break MDX parsing. Use an explicit JSX link instead:

```mdx
<Callout type="info">
  See the{" "}
  <a href="/v1/retry-policies#go-sdk-client-retry-behavior">
    Go SDK client retry behavior section
  </a>
</Callout>
```

## Fork Management

- **origin**: `https://github.com/yudaprama/hatchet` (your fork)
- **upstream**: `https://github.com/hatchet-dev/hatchet` (official repo)

### Syncing with upstream

```bash
git sync-fork
```

This runs `git fetch upstream && git rebase --autostash upstream/main`. Always rebase (not merge) to keep history linear.

### Customization commits

Your custom changes are rebased on top of upstream/main. Do not push custom commits directly to upstream. When syncing, rebase your custom branch onto the latest upstream/main.
