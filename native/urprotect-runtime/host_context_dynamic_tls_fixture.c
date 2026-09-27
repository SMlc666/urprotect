__thread int urp_dynamic_tls_value = 7;

int urp_dynamic_tls_probe(void)
{
    return urp_dynamic_tls_value;
}
