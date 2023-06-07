# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3424.1");
  script_cve_id("CVE-2015-8041", "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088", "CVE-2018-14526", "CVE-2019-11555", "CVE-2019-13377", "CVE-2019-16275", "CVE-2019-9494", "CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-22 17:15:00 +0000 (Thu, 22 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3424-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3424-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203424-1/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-6/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-6/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-1/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-2/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-4/");
  script_xref(name:"URL", value:"https://w1.fi/security/2019-5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant' package(s) announced via the SUSE-SU-2020:3424-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wpa_supplicant fixes the following issues:

wpa_supplicant was updated to 2.9 release:

 * SAE changes
 - disable use of groups using Brainpool curves
 - improved protection against side channel attacks
[[link moved to references]]
 * EAP-pwd changes
 - disable use of groups using Brainpool curves
 - allow the set of groups to be configured (eap_pwd_groups)
 - improved protection against side channel attacks
[[link moved to references]]
 * fixed FT-EAP initial mobility domain association using PMKSA caching
 (disabled by default for backwards compatibility, can be enabled with
 ft_eap_pmksa_caching=1)
 * fixed a regression in OpenSSL 1.1+ engine loading
 * added validation of RSNE in (Re)Association Response frames
 * fixed DPP bootstrapping URI parser of channel list
 * extended EAP-SIM/AKA fast re-authentication to allow use with FILS
 * extended ca_cert_blob to support PEM format
 * improved robustness of P2P Action frame scheduling
 * added support for EAP-SIM/AKA using anonymous@realm identity
 * fixed Hotspot 2.0 credential selection based on roaming consortium to
 ignore credentials without a specific EAP method
 * added experimental support for EAP-TEAP peer (RFC 7170)
 * added experimental support for EAP-TLS peer with TLS v1.3
 * fixed a regression in WMM parameter configuration for a TDLS peer
 * fixed a regression in operation with drivers that offload 802.1X
 4-way handshake
 * fixed an ECDH operation corner case with OpenSSL
 * SAE changes
 - added support for SAE Password Identifier
 - changed default configuration to enable only groups 19, 20, 21
(i.e., disable groups 25 and 26) and disable all unsuitable groups completely based on REVmd changes
 - do not regenerate PWE unnecessarily when the AP uses the anti-clogging token mechanisms
 - fixed some association cases where both SAE and FT-SAE were enabled
 on both the station and the selected AP
 - started to prefer FT-SAE over SAE AKM if both are enabled
 - started to prefer FT-SAE over FT-PSK if both are enabled
 - fixed FT-SAE when SAE PMKSA caching is used
 - reject use of unsuitable groups based on new implementation guidance in REVmd (allow only FFC groups with prime >= 3072 bits and ECC groups with prime >= 256)
 - minimize timing and memory use differences in PWE derivation
[[link moved to references]] (CVE-2019-9494, bsc#1131868)
 * EAP-pwd changes
 - minimize timing and memory use differences in PWE derivation
[[link moved to references]] (CVE-2019-9495, bsc#1131870)
 - verify server scalar/element [[link moved to references]]
(CVE-2019-9497, CVE-2019-9498, CVE-2019-9499, bsc#1131874, bsc#1131872,
bsc#1131871, bsc#1131644)
 - fix message reassembly issue with unexpected fragment
[[link moved to references]] (CVE-2019-11555, bsc#1133640)
 - enforce rand,mask generation rules more strictly
 - fix a memory leak in PWE derivation
 - disallow ECC groups with a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.9~23.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-debuginfo", rpm:"wpa_supplicant-debuginfo~2.9~23.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant-debugsource", rpm:"wpa_supplicant-debugsource~2.9~23.3.1", rls:"SLES12.0SP5"))) {
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
