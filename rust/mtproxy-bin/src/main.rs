use mtproxy_core::runtime::mtproto::config::{
    cfg_parse_config_full_pass, MtprotoConfigDefaults, MtprotoProxyTargetPassAction,
};

fn main() {
    let signature = mtproxy_core::bootstrap_signature();
    let remaining_c_units = mtproxy_core::step15::step15_remaining_c_units();
    let parse_probe = mtproto_config_parse_probe();

    match parse_probe {
        Ok((targets, clusters)) => {
            println!(
                "{signature} (step15_remaining_c_units={remaining_c_units}, parse_full_pass_targets={targets}, parse_full_pass_clusters={clusters})"
            );
        }
        Err(()) => {
            println!("{signature} (step15_remaining_c_units={remaining_c_units}, parse_full_pass_error=1)");
        }
    }
}

fn mtproto_config_parse_probe() -> Result<(usize, usize), ()> {
    let mut actions = [MtprotoProxyTargetPassAction::default(); 4];
    cfg_parse_config_full_pass::<8>(
        b"proxy dc1:443;",
        MtprotoConfigDefaults {
            min_connections: 2,
            max_connections: 64,
        },
        false,
        8,
        16,
        &mut actions,
    )
    .map(|out| (out.tot_targets, out.auth_clusters))
    .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::mtproto_config_parse_probe;

    #[test]
    fn parse_probe_uses_core_full_pass_path() {
        let out = mtproto_config_parse_probe().expect("full-pass probe should parse");
        assert_eq!(out, (1, 1));
    }
}
