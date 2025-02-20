import { useState } from "react";
import MainForm from "./components/MainForm";
import Nav from "./components/Nav";
import swal from "sweetalert";
import ReactLoading from "react-loading";

function App() {
  const [loading, setLoading] = useState(false);

  function onSubmit(url: string, scanType: string, fuzzParam?: string) {
    setLoading(true);

    const formData = {
      url: url,
      fuzzParam: fuzzParam,
    };

    fetch(`http://localhost:5000/${scanType}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(formData),
    })
      .then((response) => response.json())
      .then((data) => {
        console.log("Success:", data);

        let formattedResult = "";
        const result = data.result;

        if (result.hasOwnProperty("IP Scan")) {
          // 🟢 Formatting IP Scan results
          const ipScan = result["IP Scan"];
          formattedResult = `
            📌 **IP Scan Results**:
            - IP Address: ${ipScan.ipAddress}
            - Domain: ${ipScan.domain}
            - Country: ${ipScan.countryName}
            - Abuse Score: ${ipScan.abuseConfidenceScore}%
            - Reports: ${ipScan.totalReports}
            - Last Reported: ${ipScan.lastReportedAt}
            - Whitelisted: ${ipScan.isWhitelisted ? "✅ Yes" : "❌ No"}
          `;
        } else {
          // 🔵 Formatting URL vulnerability scan results
          formattedResult = Object.entries(result)
            .map(([key, value]) => `- **${key}**: ${value}`)
            .join("\n");
        }

        swal({
          title: "Scan Completed!",
          text: formattedResult,
          icon: "success",
          buttons: ["OK", "Cancel"],
          dangerMode: false,
        });
      })
      .catch((error) => {
        console.error("Error sending POST request:", error);
        swal({
          title: "Error!",
          text: "Failed to complete the scan.",
          icon: "error",
        });
      })
      .finally(() => {
        setLoading(false);
      });
  }

  return (
    <div className="relative h-screen">
      <Nav />
      <div className="flex justify-center">
        {loading && (
          <div className="absolute inset-0 justify-center py-64 flex z-10 text-white">
            <ReactLoading
              type={"spinningBubbles"}
              color={"#3300cc"}
              height={"10%"}
              width={"10%"}
            />
            <div className="absolute inset-0 bg-black opacity-20 z-10"></div>
          </div>
        )}
        <div className="my-24 w-1/4 relative z-0">
          <MainForm onSubmit={onSubmit} />
        </div>
      </div>
    </div>
  );
}

export default App;
