pub fn base(title: &str, body: maud::Markup) -> maud::Markup {
    maud::html! {
        (maud::DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                link rel="icon" type="image/png" sizes="32x32" href="https://conduit.rs/conduit.svg";
                style { (FONT_FACE) }
                title { (title) }
            }
            body { (body) }
        }
    }
}

pub fn footer() -> maud::Markup {
    let info = "An open network for secure, decentralized communication.";

    maud::html! {
        footer { p { (info) } }
    }
}

const FONT_FACE: &str = r#"
    @font-face {
      font-family: 'Source Sans 3 Variable';
      font-style: normal;
      font-display: swap;
      font-weight: 200 900;
      src: url(https://cdn.jsdelivr.net/fontsource/fonts/source-sans-3:vf@latest/latin-wght-normal.woff2) format('woff2-variations');
      unicode-range: U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;
    }
"#;
