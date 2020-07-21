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
                // works
                //alert(whois_data.domain_list);
                // nameservers at whois_data.nameservers are a big string.
                // need to separate it with [:SPACE:]
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