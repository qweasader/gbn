# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1135");
  script_cve_id("CVE-2019-18634", "CVE-2019-19232", "CVE-2019-19234");
  script_tag(name:"creation_date", value:"2020-02-24 09:07:29 +0000 (Mon, 24 Feb 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-06 16:00:20 +0000 (Thu, 06 Feb 2020)");

  script_name("Huawei EulerOS: Security Advisory for sudo (EulerOS-SA-2020-1135)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1135");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1135");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'sudo' package(s) announced via the EulerOS-SA-2020-1135 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"** DISPUTED ** In Sudo through 1.8.29, an attacker with access to a Runas ALL sudoer account can impersonate a nonexistent user by invoking sudo with a numeric uid that is not associated with any user. NOTE: The software maintainer believes that this is not a vulnerability because running a command via sudo as a user not present in the local password database is an intentional feature. Because this behavior surprised some users, sudo 1.8.30 introduced an option to enable/disable this behavior with the default being disabled. However, this does not change the fact that sudo was behaving as intended, and as documented, in earlier versions.(CVE-2019-19232)

** DISPUTED ** In Sudo through 1.8.29, the fact that a user has been blocked (e.g., by using the ! character in the shadow file instead of a password hash) is not considered, allowing an attacker (who has access to a Runas ALL sudoer account) to impersonate any blocked user. NOTE: The software maintainer believes that this CVE is not valid. Disabling local password authentication for a user is not the same as disabling all access to that user--the user may still be able to login via other means (ssh key, kerberos, etc). Both the Linux shadow(5) and passwd(1) manuals are clear on this. Indeed it is a valid use case to have local accounts that are _only_ accessible via sudo and that cannot be logged into with a password. Sudo 1.8.30 added an optional setting to check the _shell_ of the target user (not the encrypted password!) against the contents of /etc/shells but that is not the same thing as preventing access to users with an invalid password hash.(CVE-2019-19234)

In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS, however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.(CVE-2019-18634)");

  script_tag(name:"affected", value:"'sudo' package(s) on Huawei EulerOS V2.0SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.19p2~14.h7.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
