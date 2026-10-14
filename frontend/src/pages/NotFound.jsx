import { Link } from "react-router";

export default function NotFound() {
  return (
    <div className="shell page-empty">
      <p className="eyebrow">404</p>
      <h1>This page does not exist</h1>
      <p className="muted">Check the address, or start a new scan.</p>
      <Link to="/" className="btn btn-primary">
        Start a scan
      </Link>
    </div>
  );
}
