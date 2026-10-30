use std::{env, fs, path::Path};
fn walk(root: &Path, dir: &Path, snapshot: &Path, out: &mut String) {
    if let Ok(entries) = fs::read_dir(dir) {
        let mut paths = entries.flatten().map(|e| e.path()).collect::<Vec<_>>();
        paths.sort();
        for p in paths {
            if p.is_dir() {
                walk(root, &p, snapshot, out)
            } else {
                let name = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/");
                let target = snapshot.join(&name);
                fs::create_dir_all(target.parent().unwrap()).unwrap();
                fs::write(&target, fs::read(&p).unwrap()).unwrap();
                out.push_str(&format!(
                    "({:?},include_bytes!({:?})),\n",
                    format!("/{name}"),
                    target
                ));
            }
        }
    }
}
fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/dist");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut out = "pub static ASSETS:&[(&str,&[u8])]=&[\n".to_string();
    let snapshot = Path::new(&env::var("OUT_DIR").unwrap()).join("web-assets");
    walk(&root, &root, &snapshot, &mut out);
    out.push_str("];\n");
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("assets.rs"),
        out,
    )
    .unwrap();
}
