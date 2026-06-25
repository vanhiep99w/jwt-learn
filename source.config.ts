import { defineDocs, defineConfig } from 'fumadocs-mdx/config';
import { visit } from 'unist-util-visit';

type MdastNode = {
  type: string;
  value?: string;
  children?: MdastNode[];
  [key: string]: unknown;
};

const alertConfig: Record<string, { title: string; type: 'info' | 'warn' | 'error' }> = {
  NOTE: { title: 'NOTE', type: 'info' },
  TIP: { title: 'TIP', type: 'info' },
  IMPORTANT: { title: 'IMPORTANT', type: 'warn' },
  WARNING: { title: 'WARNING', type: 'warn' },
  CAUTION: { title: 'CAUTION', type: 'error' },
};

function getPlainText(node: MdastNode): string {
  if (typeof node.value === 'string') return node.value;
  return node.children?.map(getPlainText).join('') ?? '';
}

function removeAlertMarker(paragraph: MdastNode, marker: string) {
  const firstText = paragraph.children?.find((child) => child.type === 'text' && typeof child.value === 'string');
  if (!firstText || typeof firstText.value !== 'string') return;

  firstText.value = firstText.value.slice(marker.length).replace(/^\s*\n?\s*/, '');
}

function remarkCallouts() {
  return (tree: import('mdast').Root) => {
    visit(tree, 'blockquote', (blockquote, index, parent) => {
      const node = blockquote as unknown as MdastNode;
      const parentNode = parent as unknown as MdastNode | undefined;
      if (index === undefined || !parentNode?.children || !node.children?.length) return;

      const firstChild = node.children[0];
      if (firstChild.type !== 'paragraph') return;

      const match = getPlainText(firstChild).match(/^\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]/);
      if (!match) return;

      const marker = match[0];
      const config = alertConfig[match[1]];
      removeAlertMarker(firstChild, marker);

      const children = firstChild.children?.length && getPlainText(firstChild).trim().length > 0
        ? node.children
        : node.children.slice(1);

      parentNode.children[index] = {
        type: 'mdxJsxFlowElement',
        name: 'Callout',
        attributes: [
          {
            type: 'mdxJsxAttribute',
            name: 'title',
            value: config.title,
          },
          {
            type: 'mdxJsxAttribute',
            name: 'type',
            value: config.type,
          },
        ],
        children,
      };
    });
  };
}

function remarkMermaid() {
  return (tree: import('mdast').Root) => {
    visit(tree, 'code', (node, index, parent) => {
      if (node.lang !== 'mermaid' || index === undefined || !parent) return;
      (parent.children as unknown[])[index] = {
        type: 'mdxJsxFlowElement',
        name: 'MermaidDiagram',
        attributes: [
          {
            type: 'mdxJsxAttribute',
            name: 'chart',
            value: node.value,
          },
        ],
        children: [],
      };
    });
  };
}

export const docs = defineDocs({
  dir: 'content/docs',
});

export default defineConfig({
  mdxOptions: {
    remarkPlugins: [remarkCallouts, remarkMermaid],
  },
});
