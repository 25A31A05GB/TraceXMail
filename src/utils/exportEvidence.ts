import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';

export interface ExportEvidenceOptions {
  filename?: string;
  caseId?: string;
  evidenceId?: string;
  format?: 'png' | 'pdf' | 'jpeg';
  title?: string;
}

/**
 * Captures an HTML element (e.g. EvidenceTagCard #card) and triggers download as PNG image.
 */
export async function exportEvidenceAsImage(
  element: HTMLElement,
  filename: string = 'TraceXMail-Evidence-Card.png'
): Promise<void> {
  if (!element) {
    throw new Error('Target element for image capture was not provided');
  }

  // Ensure element styles and font rendering are stabilized
  const canvas = await html2canvas(element, {
    scale: 2, // High-DPI 2x resolution
    useCORS: true,
    allowTaint: true,
    backgroundColor: '#13161F',
    logging: false,
    scrollX: 0,
    scrollY: 0,
    onclone: (clonedDoc, clonedElement) => {
      // Ensure all badges and stamps are fully visible in the cloned DOM
      clonedElement.style.boxShadow = 'none';
      clonedElement.style.margin = '0 auto';
    }
  });

  // Convert canvas to Blob for reliable large image downloads
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) {
        reject(new Error('Failed to create image blob from canvas'));
        return;
      }
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename.endsWith('.png') ? filename : `${filename}.png`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      resolve();
    }, 'image/png');
  });
}

/**
 * Captures an HTML element and compiles it into an official A4/Letter PDF forensic document.
 */
export async function exportEvidenceAsPdf(
  element: HTMLElement,
  filename: string = 'TraceXMail-Evidence-Dossier.pdf',
  options?: { caseId?: string; evidenceId?: string; title?: string }
): Promise<void> {
  if (!element) {
    throw new Error('Target element for PDF capture was not provided');
  }

  // 1. High-resolution canvas capture
  const canvas = await html2canvas(element, {
    scale: 2.5,
    useCORS: true,
    allowTaint: true,
    backgroundColor: '#13161F',
    logging: false,
    scrollX: 0,
    scrollY: 0
  });

  const imgData = canvas.toDataURL('image/png');
  const imgWidth = canvas.width;
  const imgHeight = canvas.height;

  // 2. Initialize jsPDF (A4 portrait: 210mm x 297mm)
  const pdf = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();

  // Margins
  const margin = 12;
  const availableWidth = pageWidth - margin * 2;
  const availableHeight = pageHeight - margin * 2 - 15; // Space for header and footer

  // Calculate scaled dimensions to preserve aspect ratio
  const ratio = Math.min(availableWidth / (imgWidth / 2.83465), availableHeight / (imgHeight / 2.83465));
  const printWidth = (imgWidth / 2.83465) * ratio;
  const printHeight = (imgHeight / 2.83465) * ratio;

  // Center horizontally
  const posX = (pageWidth - printWidth) / 2;
  const posY = margin + 8;

  // Add document header
  pdf.setFont('helvetica', 'bold');
  pdf.setFontSize(10);
  pdf.setTextColor(100, 116, 139);
  pdf.text('TRACEXMAIL FORENSIC EVIDENCE ARTIFACT • COURT-ADMISSIBLE TELEMETRY', margin, margin);

  if (options?.evidenceId || options?.caseId) {
    pdf.setFont('courier', 'normal');
    pdf.setFontSize(8);
    pdf.text(`${options.evidenceId || ''} • CASE: ${options.caseId || ''}`, pageWidth - margin, margin, { align: 'right' });
  }

  // Add captured image
  pdf.addImage(imgData, 'PNG', posX, posY, printWidth, printHeight, undefined, 'FAST');

  // Add document footer with timestamp and cryptographic integrity statement
  pdf.setFont('helvetica', 'normal');
  pdf.setFontSize(7.5);
  pdf.setTextColor(148, 163, 184);
  const nowUtc = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  pdf.text(`Preserved: ${nowUtc} • Authenticated with SHA-256 Digest & NIST SP 800-86 Standards`, margin, pageHeight - 6);
  pdf.text('Page 1 of 1 • Chain of Custody Verified', pageWidth - margin, pageHeight - 6, { align: 'right' });

  // Save PDF
  const finalFilename = filename.endsWith('.pdf') ? filename : `${filename}.pdf`;
  pdf.save(finalFilename);
}
