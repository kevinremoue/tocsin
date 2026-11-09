//! History chart, drawn on the server as inline SVG: no JavaScript, colors from the CSS.
use maud::{Markup, html};

pub struct Day {
    pub day: String,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub unknown: i32,
    pub kev: i32,
    /// Not drawn: shown in the daily counts table
    pub suppressed: i32,
}

const WIDTH: f64 = 760.0;
const HEIGHT: f64 = 180.0;
const LEFT: f64 = 36.0;
const BOTTOM: f64 = 20.0;
const TOP: f64 = 8.0;

/// Stacked unsuppressed findings per severity for each day (oldest first), and a line for KEV.
pub fn history(days: &[Day]) -> Markup {
    let total = |d: &Day| d.critical + d.high + d.medium + d.low + d.unknown;
    let max = days
        .iter()
        .map(|d| total(d).max(d.kev))
        .max()
        .unwrap_or(0)
        .max(1);
    let plot_h = HEIGHT - BOTTOM - TOP;
    // Few days: narrow bars from the left, not one bar across the chart
    let slot = ((WIDTH - LEFT) / days.len().max(1) as f64).min(40.0);
    let bar = (slot * 0.7).max(1.0);
    let y = |v: i32| TOP + plot_h - f64::from(v) / f64::from(max) * plot_h;
    let x = |i: usize| LEFT + slot * i as f64 + (slot - bar) / 2.0;

    let kev_points: Vec<String> = days
        .iter()
        .enumerate()
        .map(|(i, d)| format!("{:.1},{:.1}", x(i) + bar / 2.0, y(d.kev)))
        .collect();

    html! {
        svg.chart viewBox={ "0 0 " (WIDTH) " " (HEIGHT) } role="img"
            aria-label="Unsuppressed findings per day, by severity, and KEV findings" {
            line.axis x1=(LEFT) y1=(TOP + plot_h) x2=(WIDTH) y2=(TOP + plot_h) {}
            line.axis x1=(LEFT) y1=(TOP) x2=(LEFT) y2=(TOP + plot_h) {}
            text x=(LEFT - 6.0) y=(TOP + 10.0) text-anchor="end" { (max) }
            text x=(LEFT - 6.0) y=(TOP + plot_h) text-anchor="end" { "0" }
            @if let Some(first) = days.first() {
                text x=(LEFT) y=(HEIGHT - 4.0) { (first.day) }
            }
            @if days.len() > 1 {
                @if let Some(last) = days.last() {
                    text x=(x(days.len() - 1) + bar) y=(HEIGHT - 4.0) text-anchor="end" { (last.day) }
                }
            }
            @for (i, d) in days.iter().enumerate() {
                g {
                    title {
                        (d.day) ": " (d.critical) " critical, " (d.high) " high, " (d.medium) " medium, "
                        (d.low + d.unknown) " low or unknown, " (d.kev) " KEV"
                    }
                    @for (class, value, below) in [
                        ("s1", d.low + d.unknown, 0),
                        ("s2", d.medium, d.low + d.unknown),
                        ("s3", d.high, d.low + d.unknown + d.medium),
                        ("s4", d.critical, d.low + d.unknown + d.medium + d.high),
                    ] {
                        @if value > 0 {
                            rect class=(class) x=(format!("{:.1}", x(i))) y=(format!("{:.1}", y(below + value)))
                                width=(format!("{bar:.1}"))
                                height=(format!("{:.1}", y(below) - y(below + value))) {}
                        }
                    }
                }
            }
            @if days.len() > 1 {
                polyline.kevline points=(kev_points.join(" ")) {}
            }
            @for (i, d) in days.iter().enumerate() {
                circle.kevdot cx=(format!("{:.1}", x(i) + bar / 2.0)) cy=(format!("{:.1}", y(d.kev))) r="3" {}
            }
        }
        div.legend {
            span { i.s4 {} "Critical" } span { i.s3 {} "High" } span { i.s2 {} "Medium" }
            span { i.s1 {} "Low or unknown" } span { i.kev {} "KEV" }
        }
    }
}
