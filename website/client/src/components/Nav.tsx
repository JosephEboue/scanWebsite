import { Button, Navbar } from 'flowbite-react';
import '../assets/logo.png';

function Nav() {
  return (
    <Navbar className="border border-black shadow-md "
    fluid={true}
    style={{
      backgroundColor: "#e9e9e9",
      border: "1px solid #0000",
    }}>
      <Navbar.Brand href="https://flowbite-react.com">
        <img src="/src/assets/logoPNG.png" className="mr-3 h-12 sm:h-16" alt="Logo" />
        <span className="self-center whitespace-nowrap text-2xl font-semibold dark:text-white">Vulnerability Scanner</span>
      </Navbar.Brand>
      <div className="flex md:order-2">
        <Button className='mx-8 bg-[#38B6FF]'><span className='text-lg'>Download</span></Button>
        <Navbar.Toggle />
      </div>
      <Navbar.Collapse>
        <Navbar.Link className="mx-8 text-lg" href="#" active>
          Online Version
        </Navbar.Link>
        <Navbar.Link className="mx-8 text-lg" href="#">About</Navbar.Link>
        <Navbar.Link className="mx-8 text-lg" href="#">Documentation</Navbar.Link>
      </Navbar.Collapse>
    </Navbar>
  );
}

export default Nav;