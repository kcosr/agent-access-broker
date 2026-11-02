import { useId } from "react";
import { cx } from "../lib/cx";

export interface RangeSliderProps {
  /** Visible legend and accessible group name. */
  label: string;
  /** Controlled endpoints on the min/step grid, separated by at least one step. */
  value: readonly [number, number];
  onChange: (value: [number, number]) => void;
  min: number;
  max: number;
  step?: number | undefined;
  /** Visible labels and accessible names for the two native sliders. */
  minLabel?: string | undefined;
  maxLabel?: string | undefined;
  /** Visible endpoint values and screen-reader value text (e.g. units or bands). */
  formatValue?: ((value: number) => string) | undefined;
  disabled?: boolean | undefined;
  className?: string | undefined;
}

/** Two native range inputs with independent focus and non-crossing endpoints. */
export function RangeSlider({
  label,
  value,
  onChange,
  min,
  max,
  step = 1,
  minLabel = "Minimum",
  maxLabel = "Maximum",
  formatValue = String,
  disabled = false,
  className,
}: RangeSliderProps) {
  const id = useId();
  const [lower, upper] = value;
  const onGrid = (point: number) => {
    const index = (point - min) / step;
    return Math.abs(index - Math.round(index)) < 1e-7;
  };
  if (
    ![min, max, step, lower, upper].every(Number.isFinite) ||
    step <= 0 ||
    lower < min ||
    upper > max ||
    Math.round((upper - lower) / step) < 1 ||
    ![max, lower, upper].every(onGrid)
  ) {
    throw new RangeError(
      "RangeSlider requires ordered finite endpoints within its stepped bounds",
    );
  }

  // Avoid floating-point tails in native min/max attributes for decimal steps.
  const lowerMax = Number((upper - step).toPrecision(15));
  const upperMin = Number((lower + step).toPrecision(15));
  const span = max - min;
  // Native slider travel excludes half a thumb at each end. Preserve that
  // geometry while shortening/offsetting the allowed interval on a full rail.
  const position = (start: number, end: number) => ({
    width: `calc(var(--wb-range-thumb-size) + (100% - var(--wb-range-thumb-size)) * ${(end - start) / span})`,
    insetInlineStart: `calc((100% - var(--wb-range-thumb-size)) * ${(start - min) / span})`,
  });
  const selection = {
    width: `calc((100% - var(--wb-range-thumb-size)) * ${(upper - lower) / span})`,
    insetInlineStart: `calc(var(--wb-range-thumb-size) / 2 + (100% - var(--wb-range-thumb-size)) * ${(lower - min) / span})`,
  };

  return (
    <fieldset className={cx("wb-range-slider", className)} disabled={disabled}>
      <legend className="wb-field-label">{label}</legend>
      <div className="wb-range-slider-controls">
        <label className="wb-range-slider-endpoint" htmlFor={`${id}-min`}>
          <span className="wb-range-slider-label">
            <span>{minLabel}</span>
            <span className="wb-range-slider-value" aria-hidden="true">
              {formatValue(lower)}
            </span>
          </span>
          <span className="wb-range-slider-track">
            <span
              className="wb-range-slider-selection"
              style={selection}
              aria-hidden="true"
            />
            <input
              id={`${id}-min`}
              style={position(min, lowerMax)}
              type="range"
              min={min}
              max={lowerMax}
              step={step}
              value={lower}
              aria-valuetext={formatValue(lower)}
              onChange={(event) => {
                if (disabled) return;
                const next = Math.max(
                  min,
                  Math.min(lowerMax, event.currentTarget.valueAsNumber),
                );
                if (Number.isFinite(next) && next !== lower)
                  onChange([next, upper]);
              }}
            />
          </span>
        </label>
        <label className="wb-range-slider-endpoint" htmlFor={`${id}-max`}>
          <span className="wb-range-slider-label">
            <span>{maxLabel}</span>
            <span className="wb-range-slider-value" aria-hidden="true">
              {formatValue(upper)}
            </span>
          </span>
          <span className="wb-range-slider-track">
            <span
              className="wb-range-slider-selection"
              style={selection}
              aria-hidden="true"
            />
            <input
              id={`${id}-max`}
              style={position(upperMin, max)}
              type="range"
              min={upperMin}
              max={max}
              step={step}
              value={upper}
              aria-valuetext={formatValue(upper)}
              onChange={(event) => {
                if (disabled) return;
                const next = Math.min(
                  max,
                  Math.max(upperMin, event.currentTarget.valueAsNumber),
                );
                if (Number.isFinite(next) && next !== upper)
                  onChange([lower, next]);
              }}
            />
          </span>
        </label>
      </div>
    </fieldset>
  );
}
