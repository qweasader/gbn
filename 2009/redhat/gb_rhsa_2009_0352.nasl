# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63757");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0586");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:0352");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0352.

GStreamer is a streaming media framework based on graphs of filters which
operate on media data. GStreamer Base Plug-ins is a collection of
well-maintained base plug-ins.

An integer overflow flaw which caused a heap-based buffer overflow was
discovered in the Vorbis comment tags reader. An attacker could create a
carefully-crafted Vorbis file that would cause an application using
GStreamer to crash or, potentially, execute arbitrary code if opened by a
victim. (CVE-2009-0586)

All users of gstreamer-plugins-base are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue. After
installing this update, all applications using GStreamer (such as Totem or
Rhythmbox) must be restarted for the changes to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0352.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gstreamer-plugins-base", rpm:"gstreamer-plugins-base~0.10.20~3.0.1.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-plugins-base-debuginfo", rpm:"gstreamer-plugins-base-debuginfo~0.10.20~3.0.1.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-plugins-base-devel", rpm:"gstreamer-plugins-base-devel~0.10.20~3.0.1.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
