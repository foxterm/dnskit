#include "shim.h"

uint16_t ns_msg_get_id(ns_msg handle) {
    return ns_msg_id(handle);
}

uint16_t ns_msg_get_base(ns_msg handle) {
    return ns_msg_base(handle);
}

uint16_t ns_msg_get_end(ns_msg handle) {
    return ns_msg_end(handle);
}

uint16_t ns_msg_get_size(ns_msg handle) {
    return ns_msg_size(handle);
}

uint16_t ns_msg_get_count(ns_msg handle, int section) {
    return ns_msg_count(handle, section);
}
