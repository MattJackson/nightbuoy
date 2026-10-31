<script lang="ts">
 import {postBlocks,type Inline} from './lib/post-text';
 let {text}:{text:string}=$props();
 const blocks=$derived(postBlocks(text));
</script>
{#snippet inline(parts:Inline[])}
 {#each parts as part}
  {#if part.kind==='bold'}<strong>{part.text}</strong>
  {:else if part.kind==='italic'}<em>{part.text}</em>
  {:else if part.kind==='strike'}<s>{part.text}</s>
  {:else if part.kind==='code'}<code>{part.text}</code>
  {:else if part.kind==='spoiler'}<details class="post-spoiler"><summary>Spoiler</summary><span>{part.text}</span></details>
  {:else if part.kind==='link'&&part.url}<a href={part.url} target="_blank" rel="noopener noreferrer nofollow" referrerpolicy="no-referrer" title={part.url}>{part.text}</a>
  {:else}{part.text}{/if}
 {/each}
{/snippet}
<div class="formatted-post">
 {#each blocks as block}
  {#if block.kind==='code'}<pre><code>{block.text}</code></pre>
  {:else if block.kind==='list'}
   {#if block.ordered}<ol start={block.start??1}>{#each block.items as item}<li>{@render inline(item)}</li>{/each}</ol>
   {:else}<ul>{#each block.items as item}<li>{@render inline(item)}</li>{/each}</ul>{/if}
  {:else if block.kind==='heading'}<svelte:element this={`h${(block.level??1)+2}`}>{@render inline(block.parts)}</svelte:element>
  {:else if block.kind==='quote'}<blockquote>{@render inline(block.parts)}</blockquote>
  {:else}<div class="post-paragraph">{@render inline(block.parts)}</div>{/if}
 {/each}
</div>
