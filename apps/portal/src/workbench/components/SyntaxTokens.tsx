import { Fragment } from "react";
import type { CSSProperties } from "react";

export type SyntaxToken = {
  readonly content: string;
  readonly style: CSSProperties;
};

export type SyntaxLines = readonly (readonly SyntaxToken[])[];

/**
 * Already-tokenized code as text spans. The caller supplies the code container,
 * tokenizer and its styles; this component only preserves the tokens and line
 * breaks. Include an empty final line when the source ends with a newline.
 */
export function SyntaxTokens({ lines }: { lines: SyntaxLines }) {
  return (
    <>
      {lines.map((line, lineIndex) => (
        <Fragment key={lineIndex}>
          {lineIndex > 0 && "\n"}
          {line.map((token, tokenIndex) => (
            <span
              key={tokenIndex}
              className="wb-syntax-token"
              style={token.style}
            >
              {token.content}
            </span>
          ))}
        </Fragment>
      ))}
    </>
  );
}
