# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882093");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-23 12:56:27 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-7823");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for libvirt CESA-2015:0008 centos7");
  script_tag(name:"summary", value:"Check the version of libvirt");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

It was found that when the VIR_DOMAIN_XML_MIGRATABLE flag was used, the
QEMU driver implementation of the virDomainGetXMLDesc() function could
bypass the restrictions of the VIR_DOMAIN_XML_SECURE flag. A remote
attacker able to establish a read-only connection to libvirtd could use
this flaw to leak certain limited information from the domain XML data.
(CVE-2014-7823)

This issue was discovered by Eric Blake of Red Hat.

This update also fixes the following bugs:

  * In Red Hat Enterprise Linux 6, libvirt relies on the QEMU emulator to
supply the error message when an active commit is attempted. However, with
Red Hat Enterprise Linux 7, QEMU added support for an active commit, but an
additional interaction from libvirt to fully enable active commits is still
missing. As a consequence, attempts to perform an active commit caused
libvirt to become unresponsive. With this update, libvirt has been fixed to
detect an active commit by itself, and now properly declares the feature as
unsupported. As a result, libvirt no longer hangs when an active commit is
attempted and instead produces an error message.

Note that the missing libvirt interaction will be added in Red Hat
Enterprise Linux 7.1, adding full support for active commits. (BZ#1150379)

  * Prior to this update, the libvirt API did not properly check whether a
Discretionary Access Control (DAC) security label is non-NULL before trying
to parse user/group ownership from it. In addition, the DAC security label
of a transient domain that had just finished migrating to another host is
in some cases NULL. As a consequence, when the virDomainGetBlockInfo API
was called on such a domain, the libvirtd daemon sometimes terminated
unexpectedly. With this update, libvirt properly checks DAC labels before
trying to parse them, and libvirtd thus no longer crashes in the described
scenario. (BZ#1171124)

  * If a block copy operation was attempted while another block copy was
already in progress to an explicit raw destination, libvirt previously
stopped regarding the destination as raw. As a consequence, if the
qemu.conf file was edited to allow file format probing, triggering the bug
could allow a malicious guest to bypass sVirt protection by making libvirt
regard the file as non-raw. With this update, libvirt has been fixed to
consistently remember when a block copy destination is raw, and guests can
no longer circumvent sVirt protection when the ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"libvirt on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0008");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-January/020859.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-kvm", rpm:"libvirt-daemon-kvm~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-lxc", rpm:"libvirt-daemon-lxc~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-login-shell", rpm:"libvirt-login-shell~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~1.1.1~29.el7_0.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}