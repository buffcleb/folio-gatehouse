# Access Logs

Every file request intercepted by the plugin is recorded in the **Logs tab**. The log stores the timestamp, user, IP address, file path, and whether access was granted or denied.

---

## Log table columns

| Column | Description |
|---|---|
| Time | Date and time of the request |
| User | WordPress username, or `Guest` for unauthenticated requests |
| Roles | The user's roles at the time of the request |
| IP | Client IP address |
| Path | Relative path to the requested file |
| Status | `Granted` or `Denied` |

Click any column header to sort. Click again to reverse direction.

---

## Filtering

The filter bar at the top of the tab supports:

- **Date From / Date To** — `datetime-local` pickers. You can set one or both:
  - Both set → records between the two datetimes.
  - Only From → records from that datetime onward.
  - Only To → records up to that datetime.
- **Username** — partial match. Type `guest` to filter guest (unauthenticated) requests.
- **IP** — partial match, useful for filtering by subnet prefix (e.g. `192.168.1`).
- **Path** — partial match against the file path.
- **Status** — exact match: `Granted` or `Denied`.

Apply filters with **Apply Filters**. Reset with **Clear Filters**.

---

## Pagination

Choose rows per page from the selector: 10, 25, 50, 100, 250, 500, or All. Default is 25.

---

## Stats widget

Above the filter bar, a stats bar shows:
- Total log entries matching the current filters.
- Granted count.
- Denied count.
- A 7-day activity sparkline.

---

## CSV export

Click **Export CSV** to download the full filtered dataset as a CSV file. The export:
- Applies all active filters.
- Preserves the current sort column and direction.
- Always returns every matching record (not just the current page).
- Includes a UTF-8 BOM so Excel interprets the encoding correctly.

---

## Log pruning

### Automatic pruning

In **Settings → Log Retention**, set a retention period in days and enable the daily cron. The cron runs once per day and deletes records older than the configured period.

### Manual pruning

Click the **Prune Logs** button in the **Settings tab**. A confirmation dialog lists how many records will be deleted before you confirm.
