// Sidebar javascript
//* Loop through all dropdown buttons to toggle between hiding and showing its dropdown content - This allows the user to have multiple dropdowns without any conflict */
let dropdown = document.getElementsByClassName("dropdown-btn");
let i;

for (i = 0; i < dropdown.length; i++) {
  dropdown[i].addEventListener("click", function() {
    this.classList.toggle("active");
    let dropdownContent = this.nextElementSibling;
    if (dropdownContent.style.display === "block") {
      dropdownContent.style.display = "none";
    } else {
      dropdownContent.style.display = "block";
    }
  });
}

//HIDE BUTTONS

const arp_btn = document.getElementById("arp-btn");
const syn_btn = document.getElementById("syn-btn");
const grab_btn = document.getElementById("grab-btn");


arp_btn.onclick = function () {

  document.getElementById("icmp-btn").style.visibility="hidden";
  document.getElementById("arp-btn").style.visibility="hidden";

};

syn_btn.onclick = function() {
      document.getElementById("syn-btn").style.visibility="hidden";

};

grab_btn.onclick = function () {
    document.getElementById("grab-btn").style.visibility = "hidden";

};


//ARP SCAN
$(document).ready(function () {
    $('#arp-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsArp/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend(arp-btn) run!!');
            },
            success: function (arp_data) {
                // by default table with results is hidden.
                $("#results_table").show();
                // alert(arp_data.message);
                //let res_table = $("#lan_table_results tbody")
                let res_table_ip = $("#lan_table_results tbody tr #ips")
                let res_table_mac = $("#lan_table_results tbody tr #macs")
                let ips = arp_data.ip_addresses
                let macs = arp_data.mac_addresses
                console.log(ips)
                console.log(macs)
                let i
                for (i=0 ; i<ips.length ; i++)
                {
                        res_table_ip.append("<tr><td>" + ips[i] + "</td></tr>")
                        res_table_mac.append("<tr><td>" + macs[i] + "</td></tr>")
                        //res_table.append("<tr><td>" +  ips[i] + "</td><td>" + macs[i] + "</td></tr>");

                }
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed ajax for arp-btn!');
            }
        });
    });
});

//Host-alive SCAN
$(document).ready(function () {
    $('#icmp-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsIcmp/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend for icmp-btn');
            },
            success: function (data) {
                // message passed from views.py!
                alert(data.message);
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Ajax completed for icmp-btn');
            }
        });
    });
});

//SYN-SCAN
$(document).ready(function () {
    $('#syn-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsSyn/",
            beforeSend: () => {
                 $(".ajax_loader").show();
                 console.log('BeforeSend function(syn-btn) run');
            },
            success: function (new_data) {
                console.log(new_data.port_results)
                let res_table_ports = $("#lan_table_results tbody tr #ports")
                $(jQuery.parseJSON(JSON.stringify(new_data.port_results))).each(function() {
                        let _PORTS = this.PORTS;
                        let PORTS
                        if (_PORTS === "")
                        {
                            PORTS = "--"
                        }else {
                            // remove redundant comma at the end of each string
                            PORTS = _PORTS.slice(0, -1)
                        }
                        console.log(PORTS)
                        res_table_ports.append("<tr><td>" + PORTS + "</td></tr>")
                    });
            },
            complete: () => {
                 $(".ajax_loader").hide();
                console.log('Completed ajax for syn-btn!');
            }
        });
    });
});

//Banner-grabber
$(document).ready(function () {
    $('#grab-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsGrab/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend function(grab-btn) run!!');
            },
            success: function (data) {
                //console.log(data.grabber_results)
                let res_table_services = $("#lan_table_results tbody tr #banners")
                $(jQuery.parseJSON(JSON.stringify(data.grabber_results))).each(function() {
                        let SERVICES = this.SERVICES;
                        if (SERVICES === "")
                        {
                            SERVICES = "--"
                        }
                        console.log(SERVICES)
                        res_table_services.append("<tr><td>" + SERVICES + "</td></tr>")
                    });
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed ajax for grab-btn!');
            }
        });
    });
});

// CVE-search
$(document).ready(function () {
    $('#cve-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsCVEs/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend function(find-cves-btn) run!!');
            },
            success: function (data) {
                $("#cve_table").show();
                console.log(data.cve_results)
                let res_table_cves = $("#cve_results_table tbody tr #cve")
                let res_table_desc = $("#cve_results_table tbody tr #description")
                let res_table_serv_cve = $("#cve_results_table tbody tr #serv_cve")
                $(jQuery.parseJSON(JSON.stringify(data.cve_results))).each(function() {
                        let CVE = this.CVE;
                        let DESC = this.DESCRIPTION;
                        let SERV_CVE = this.SERVICE_CVE;
                        if (CVE === "")
                        {
                            CVE = "--"
                            DESC = "--"
                        }
                        console.log(CVE)
                        res_table_cves.append("<tr><td>" + CVE + "</td></tr>")
                        res_table_desc.append("<tr><td>" + DESC + "</td></tr>")
                        //res_table_service.append("<tr><td>" + SERVICE + "</td></tr>")
                        res_table_serv_cve.append("<tr><td class='border border-danger'>" + SERV_CVE + "</td></tr>")
                    });

            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed ajax call');
            }
        });
    });
});

// $(document).ready(function () {
//     $('#spoof-btn').click(function () {
//         $.ajax({
//             type: "POST",
//             url: "/dashboard/Exploitation/",
//             beforeSend: () => {
//                 console.log('BeforeSend(arp-btn) run!!');
//             },
//             success: function (some_data) {
//                 console.log("WTF")
//             },
//             complete: () => {
//                 $(".ajax_loader").hide();
//                 console.log('Completed ajax for arp-spoof btn');
//             }
//         });
//     });
// });
// Event listener for BackWards button.
history.pushState(null, document.title, location.href);
window.addEventListener('popstate', function (event)
{
    const leavePage = confirm("Are you sure you want to go back? Project results will not be saved");
    if (leavePage) {
        history.back();
    } else {
        history.pushState(null, document.title, location.href);
    }
});
