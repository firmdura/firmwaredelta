/* Copyright 2026 FirmwareDelta contributors
 * SPDX-License-Identifier: Apache-2.0 */

extern int maintenance_value(void);
#ifdef WITH_EXTRA
extern int extra_value(void);
#endif

int main(void) {
#ifdef WITH_EXTRA
    return maintenance_value() + extra_value();
#else
    return maintenance_value();
#endif
}
