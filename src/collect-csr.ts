import { promises as fs } from 'fs';
import { pki } from 'node-forge';
import path from 'path';

const certsDir = __dirname;

(async () => {
  
  try {

    const csrByPath = await collect(certsDir);
  
    const csrOutput = JSON.stringify(csrByPath);
    
    const outputFilePath = path.join(__dirname, '__COLLECTED__CSRS___.json');

    console.log(`WRITING CSRS TO ${outputFilePath}`);

    await fs.writeFile(outputFilePath, csrOutput);

  } catch (error) {

    console.error(error);

  }

})();


async function collect(dirPath) {

  const now = new Date();

  const csrByPath = {};

  const items = await fs.readdir(dirPath);

  for (const item of items) {
    const itemPath = path.join(dirPath, item);
    const stat = await fs.stat(itemPath);

    if (stat.isDirectory()) {
      const moreCsrs = await collect(itemPath);
      Object.assign(csrByPath, moreCsrs);
    }

    if (stat.isFile()) {

      if (item.match(/^.*cert\.pem$/)) {
        
        const certPem = await fs.readFile(itemPath, 'utf8');
        const cert = pki.certificateFromPem(certPem);

        console.log(itemPath);
        console.log(cert.validity.notAfter);

        if (cert.validity.notAfter <= now) {
          csrByPath[itemPath] = {
            csr: await createCsr(cert, itemPath)
          };
        }

      }
    }
  }

  return csrByPath;
}



async function createCsr(cert, path) {

  const keyPath = path.replace(/\.cert\.pem$/, '.key.pem');

  const privateKeyPem = await fs.readFile(keyPath, 'utf8');

  const privateKey = pki.privateKeyFromPem(privateKeyPem);

  const csr = pki.createCertificationRequest();

  csr.extensions = cert.extensions;

  csr.subject = cert.subject;

  csr.publicKey = cert.publicKey;

  csr.sign(privateKey);

  const csrPem = pki.certificationRequestToPem(csr);

  return csrPem;
};
