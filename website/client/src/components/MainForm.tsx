import React, { useState } from 'react';
import { Button, Label, TextInput } from 'flowbite-react';

interface Props {
  onSubmit: (url: string, scanType: string, fuzzParam?: string) => void;
}

function MainForm({ onSubmit }: Props) {
  const [url, setUrl] = useState('');
  const [fuzzParam, setFuzzParam] = useState('');


  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
      onSubmit(url, 'all-scan', fuzzParam);
  };

  return (
    <form className="flex max-w-md flex-col gap-4" onSubmit={handleSubmit}> 
      <div>
        <div className="mb-2 block">
          <Label htmlFor="url" value="URL or IP" />
        </div>
        <TextInput
          id="url"
          type="text"
          placeholder="http://localhost:8080/"
          required
          shadow
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
      </div>


        <div>
          <div className="mb-2 block">
            <Label htmlFor="fuzz-param" value="fuzz parameter" />
          </div>
          <TextInput
            id="fuzz-param"
            type="text"
            required
            shadow
            value={fuzzParam}
            onChange={(e) => setFuzzParam(e.target.value)}
          />
        </div>

      <Button className='bg-[#38B6FF]' type="submit">Scan site for vulnerabilities</Button>
    </form>
  );
}

export default MainForm;
