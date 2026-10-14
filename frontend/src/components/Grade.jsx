const TONE = { A: "ok", B: "low", C: "medium", D: "high", F: "critical" };

/** Letter grade tile. `size` is "sm" for lists, "lg" for the report header. */
export default function Grade({ grade, size = "sm", label }) {
  if (!grade) return <span className={`grade grade-${size} grade-none`} aria-label="Not graded">–</span>;
  return (
    <span className={`grade grade-${size} tone-${TONE[grade]}`} aria-label={label || `Grade ${grade}`} title={label || `Grade ${grade}`}>
      {grade}
    </span>
  );
}
