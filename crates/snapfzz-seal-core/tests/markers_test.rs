use snapfzz_seal_core::types::*;

#[test]
fn no_searchable_strings() {
    for i in 0..5 {
        let marker = get_secret_marker(i);
        let marker_str = String::from_utf8_lossy(marker);
        assert!(!marker_str.contains("SECRET"));
        assert!(!marker_str.contains("MARKER"));
        assert!(!marker_str.contains("ASL"));
    }
}

#[test]
fn markers_are_unique() {
    let markers: Vec<_> = (0..5).map(get_secret_marker).collect();

    for i in 0..markers.len() {
        for j in (i + 1)..markers.len() {
            assert_ne!(markers[i], markers[j]);
        }
    }
}
