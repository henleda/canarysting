// Spark renders the escalation sparkline (`.spark` in the prototype): a row of
// bars whose heights are the flow's real per-event suspicion-score progression,
// already normalized to [0,1] by the backend (FlowView.spark_series). When there
// is no series, it renders a quiet flat baseline (no fabricated curve).
interface SparkProps {
  series: number[] | null | undefined;
}

const FLAT_BARS = 48;
const MIN_HEIGHT = 5; // %, so even a 0 sample shows a sliver (matches prototype's floor)

export default function Spark({ series }: SparkProps) {
  const bars = series && series.length > 0 ? series : Array<number>(FLAT_BARS).fill(0);
  return (
    <div className="spark">
      {bars.map((h, i) => (
        <i key={i} style={{ height: `${Math.max(MIN_HEIGHT, Math.round(h * 100))}%` }} />
      ))}
    </div>
  );
}
