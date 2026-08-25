## The legacy `/dashboard` route is gone

`/dashboard` served an HTML surface that `bernstein gui serve` has replaced.
The route, its package and its static assets are removed, and `bernstein
dashboard` now exits with a pointer to `bernstein gui serve` and the
`bernstein[gui]` extra it needs (#4395).
