# Pinned Fedora 44 akmods

This local BlueBuild module preserves the reviewed upstream NVIDIA Open installation flow while pinning both common and NVIDIA RPM image inputs. The distinct module name avoids BlueBuild0.9.37 automatic mutable akmods staging.

Only Fedora44, amd64, main kernel, empty extra-module list, NVIDIA Open, and MULTILIB=0 are accepted. Before any installation/network command, the module validates its exact configuration and installed kernel-core7.2.10-200.fc44.x86_64. After installation, kernel-core, NVIDIA kernel/userspace/module versions and the module vermagic kernel must agree. These are build checks, not hardware, MOK/SecureBoot, or native boot qualification. Userspace package repository resolution remains outside the akmods OCI pin boundary.

Provenance and local modifications are recorded in UPSTREAM_SOURCE.json. INPUT_REVIEW.json records the current exact-digest vendor signature and kernel metadata review, including the remaining installed-image checks. Update the base/kernel and both input digests together after signature and compatibility review. A fresh real installed-image build and driver verification are required after every input change. Never run this installer against the development host.
