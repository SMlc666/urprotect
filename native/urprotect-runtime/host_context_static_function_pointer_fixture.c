typedef unsigned long urp_word;
typedef urp_word (*urp_callback)(urp_word);

__attribute__((noinline, used, visibility("hidden")))
urp_word urp_static_callback(urp_word value)
{
    return value + 17;
}

__attribute__((noinline, used, visibility("default")))
int urp_entry(void *context)
{
    urp_callback volatile callback = urp_static_callback;
    urp_word value = (urp_word)context;
    return callback(value) == value + 17 ? 97 : 96;
}

__attribute__((noinline, used, visibility("default")))
int urp_observer(void *context)
{
    urp_callback volatile callback = urp_static_callback;
    urp_word value = (urp_word)context;
    return callback(value) == value + 17 ? 97 : 96;
}
