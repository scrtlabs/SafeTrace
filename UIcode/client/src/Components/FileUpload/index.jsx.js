import React, { useState } from "react";

const FileUpload = ({ placeholder = "Choose file", onChange, onSubmit }) => {
  const [file, setFile] = useState("");
  const [filename, setFilename] = useState("");

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length) {
      if (onChange && onChange instanceof Function) {
        const valid = onChange(e.target.files[0]);
        if (valid === false) {
          setFile("");
          setFilename("");
          return;
        }
      }
      setFile(e.target.files[0]);
      setFilename(e.target.files[0].name);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit(file);
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="custom-file mb-4">
        <input
          type="file"
          className="custom-file-input"
          id="customFile"
          onChange={handleFileChange}
        />
        <label className="custom-file-label" htmlFor="customFile">
          {filename || placeholder}
        </label>
      </div>

      <input
        type="submit"
        value="Upload"
        className="btn btn-primary btn-block mt-4"
      />
    </form>
  );
};

export default FileUpload;
