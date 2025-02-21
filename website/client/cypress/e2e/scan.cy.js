describe("Authentication Flow", () => {
    const rootpage = "http://127.0.0.1:5173/";
  
  
    it("should write inputs with Url", () => {
      cy.visit(rootpage);
  
      // Fill out the sign-up form
      cy.get('input[placeholder="http://localhost:8080/"]').type('http://netflx-actualizar.com/');
      cy.get('input[id="fuzz-param"]').type("' OR '1'='1' -- ");
      cy.contains("Scan site for vulnerabilities").click();
      cy.wait(1000);
    });

    it("should write inputs with Ip", () => {
        cy.visit(rootpage);
    
        // Fill out the sign-up form
        cy.get('input[placeholder="http://localhost:8080/"]').type('170.64.174.143');
        cy.get('input[id="fuzz-param"]').type("' OR '1'='1' -- ");
        cy.contains("Scan site for vulnerabilities").click();
      });
  });
  