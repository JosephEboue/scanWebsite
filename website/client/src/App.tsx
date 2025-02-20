import { useState } from "react";
import MainForm from "./components/MainForm";
import Nav from "./components/Nav";
import swal from "sweetalert";
import ReactLoading from "react-loading";

function App() {
  const [loading, setLoading] = useState(false);

  function onSubmit(url: string, scanType: string, fuzzParam?: string) {
    setLoading(true);

    var formData = {};

    //if (scanType === 'fuzz' || scanType === 'all') {
    formData = {
      url: url,
      fuzzParam: fuzzParam,
    };
    /*} else {
      formData = {
        url: url,
      };
    }*/

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

        // Format the result object into a readable string
        const formattedResult = Object.entries(data.result)
          .map(([key, value]) => `${key}: ${value}`)
          .join("\n"); // Join each entry with a newline

        swal({
          title: "Scan completed!",
          text: formattedResult, // Now properly formatted
          icon: "success",
          buttons: ["OK", "Cancel"],
          dangerMode: false,
        });
      })

      .catch((error) => console.error("Error sending POST request:", error))
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
            <div className="absolute inset-0  bg-black opacity-20 z-10"></div>
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
