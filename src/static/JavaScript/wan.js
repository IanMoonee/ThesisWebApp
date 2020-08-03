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

// WhoisLookup
$(document).ready(function () {
    $('#whois-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/WanDashboard/whoisLookup/",
            dataType: 'json',
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend whoisLookup');
            },
            success: function (whois_data) {
                let splitted_array_nameservers = whois_data.nameservers.split(" ");
                // console.log(splitted_array_nameservers);
                $("#result_whois_table").show();
                let whois_table = $("#result_whois_table tbody");
                whois_table.append("<tr><td>" + whois_data.domain_list + "</td>" + "<td>" + whois_data.whois_server+"</td>"+ "<td>" + whois_data.nameservers+"</td>"
                + "<td>" + whois_data.emails+"</td>"+ "<td>" + whois_data.address+"</td>"+ "<td>" + whois_data.city+"</td>")
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed whois ajax request.');
            }
        });
    });
});


// recursive dns
$(document).ready(function () {
    $('#recdns-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/WanDashboard/recursiveDns/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend recursiveDNS');
            },
            success: function (results) {
                console.log(results)
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed recDns ajax request.');
            }
        });
    });
});

// SYN port scanner scapy
$(document).ready(function () {
    $('#portscan-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/WanDashboard/portScanner/",
            dataType: 'json',
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend portScanner');
            },
            success: function (portScan_data) {
                // $("#result_whois_table").show();
                alert(portScan_data.message)
                let whois_table = $("#result_whois_table tbody");
                whois_table.append("<tr><th scope='col'>Open Ports</th><td>" + portScan_data.open_ports + "</td></tr>");

            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed PortScan Ajax request.');
            }
        });
    });
});

// banner grabber
$(document).ready(function () {
    $('#bannergrab-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/WanDashboard/bannerGrabber/",
            dataType: 'json',
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend BannerGrabber Ajax.');
            },
            success: function (portScan_data) {
                // $("#result_whois_table").show();
                alert(portScan_data.message)
                let whois_table = $("#result_whois_table tbody");
                whois_table.append("<tr><th scope='col'>Services Running</th><td>" + portScan_data.services + "</td></tr>");

            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed bannerGrabber ajax.');
            }
        });
    });
});

// subdomain scanner
$(document).ready(function () {
    $('#subdomains-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/WanDashboard/subDomains/",
            dataType: 'json',
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend SubDomain Enum Ajax.');
            },
            success: function (response_data) {
                // $("#result_whois_table").show();
                alert('Subdomain Enumeration Finished.')
                let whois_table = $("#result_whois_table tbody");
                whois_table.append("<tr><th scope='col'>Discovered Subdomains</th><td>" +  response_data.subdomains_found + "</td></tr>");
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed SubDomain Enum Ajax');
            }
        });
    });
});

// banner grabber
// $(document).ready(function () {
//     $('#test-btn').click(function () {
//         $.ajax({
//             type: "GET",
//             url: "/WanDashboard/test/",
//             dataType: 'json',
//             beforeSend: () => {
//                 $(".ajax_loader").show();
//                 console.log('BeforeSend test Ajax.');
//             },
//             success: function (portScan_data) {
//                 // $("#result_whois_table").show();
//                 alert('Test called');
//             },
//             complete: () => {
//                 $(".ajax_loader").hide();
//                 console.log('Completed test ajax.');
//             }
//         });
//     });
// });

$(document).ready(function () {
    $('#bruteforce-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/WanDashboard/directoryFuzzing/",
            dataType: 'json',
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend fuzzer .');
            },
            success: function (fuzzed_data) {
                alert('Directory fuzzing completed.');
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed fuzzer ajax.');
            }
        });
    });
});

