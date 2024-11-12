/*
 * Author: rohmxx
 * Date: 2024-11-07
 * Description: Adafruit Fingerprint Address Password Checker and Image Extractor.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Drawing.Imaging;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO.Ports;
using System.Threading;
using System.IO;
using System.Runtime.InteropServices;

namespace Fingerprint_Scanner
{
    public partial class Form1 : Form
    {
        string selectedCOM = "";
        byte[] start_code = { 0xEF, 0x01 };
        byte[] f_address = { 0x00, 0x00, 0x00, 0x00 };
        byte[] data_type = { 0x01, 0x00 };
        byte[] wire_len = { 0x07, 0x13 };
        byte[] f_password = { 0x00, 0x00, 0x00, 0x00 };
        byte[] data_sum = { 0x00, 0x00 };

        public Form1()
        {
            InitializeComponent();
            string[] ports = SerialPort.GetPortNames();
            comboBox1.Text = "";
            comboBox1.Items.Clear();
            foreach (string port in ports)
            {
                comboBox1.Items.Add(port);
                comboBox1.SelectedItem = port;
            }
        }

        void fingerpinrt_thread()
        {
            byte[] read_buffer = new byte[12];
            read_buffer[9] = 0xFF;
            int totalLength = start_code.Length + f_address.Length + data_type.Length + wire_len.Length + f_password.Length + data_sum.Length;
            byte[] send_buffer = new byte[totalLength];
            data_sum[1] = (byte)(data_type[0] + data_type[1] + wire_len[0] + wire_len[1]);
            while (!(read_buffer[9] == 0x00))
            {
                int index = 0;
                foreach (byte[] array in new byte[][] { start_code, f_address, data_type, wire_len, f_password, data_sum })
                {
                    foreach (byte b in array)
                    {
                        send_buffer[index++] = b;
                    }
                }
                //veriv EF 01 FF FF FF FF 01 00 07 13 00 00 00 00 00 1B
                serialPort1.Write(send_buffer, 0, send_buffer.Length);
                Thread.Sleep(1);
                if (serialPort1.BytesToRead >= 12)
                    serialPort1.Read(read_buffer, 0, 12);
                Thread.Sleep(1);
                if (read_buffer[9] == 0x20)
                {
                    f_address[0] = read_buffer[2];
                    f_address[1] = read_buffer[3];
                    f_address[2] = read_buffer[4];
                    f_address[3] = read_buffer[5];
                }
                this.Invoke((MethodInvoker)delegate ()
                {
                    richTextBox1.Text = "MENCARI\n";
                });
                Thread.Sleep(100);
            }
            this.Invoke((MethodInvoker)delegate ()
            {
                richTextBox1.Text = "Address: \n" + BitConverter.ToString(f_address) + "\nScan Jari";
            });
            read_buffer[9] = 0xFF;
            int counter = 0;
            //getimg     EF 01 FF FF FF FF 01 00 03 01 00 05
            byte[] getimage =   { 0xEF, 0x01, f_address[0], f_address[1], f_address[2], f_address[3], 0x01, 0x00, 0x03, 0x01, 0x00, 0x05 };
            //showfinger EF 01 FF FF FF FF 01 00 03 0a 00 0e
            byte[] showfinger = { 0xEF, 0x01, f_address[0], f_address[1], f_address[2], f_address[3], 0x01, 0x00, 0x03, 0x0a, 0x00, 0x0e };
            while (counter <= 2)
            {
                serialPort1.Write(getimage, 0, getimage.Length);
                Thread.Sleep(250);
                if (serialPort1.BytesToRead >= 12)
                    serialPort1.Read(read_buffer, 0, 12);
                Console.WriteLine(BitConverter.ToString(read_buffer) + "\n");
                if (read_buffer[9] == 0x00 && read_buffer[11] == 0x0A)
                {
                    counter += 1;
                    read_buffer[9] = 0xFF;
                }
                else
                {
                    this.Invoke((MethodInvoker)delegate ()
                    {
                        richTextBox1.Text = "Address: \n" + BitConverter.ToString(f_address) + "\nScan Jari\nJari undetected";
                    });
                    counter = 0;
                }
            }
            this.Invoke((MethodInvoker)delegate ()
            {
                richTextBox1.Text = "Address: \n" + BitConverter.ToString(f_address) + "\nJari detected\nLoad scan...\nMohon tunggu";
            });
            serialPort1.DiscardInBuffer();
            Thread.Sleep(100);
            counter = 0;
            serialPort1.Write(showfinger, 0, showfinger.Length);
            while (serialPort1.BytesToRead < 40044) ;
            counter = serialPort1.BytesToRead;
            byte[] fingerbuff = new byte[counter];
            byte[] fingerhex = new byte[36864];
            if(serialPort1.BytesToRead >= counter)
            {
                serialPort1.Read(fingerbuff, 0, counter);
            }
            counter = 0;
            UInt16 j = 0;
            byte[] confirm = { 0xEF, 0x01, f_address[0], f_address[1], f_address[2], f_address[3], 0x07, 0x00, 0x03, 0x00 };
            byte[] sequence = { 0xEF, 0x01, f_address[0], f_address[1], f_address[2], f_address[3] };
            for (int i = 0; i < fingerbuff.Length; i++)
            {
                if (i == 0 && fingerbuff.Take(confirm.Length).SequenceEqual(confirm))
                {
                    i += 11;
                    continue;
                }
                else if(i == 0 && !fingerbuff.Take(confirm.Length).SequenceEqual(confirm))
                {
                    this.Invoke((MethodInvoker)delegate ()
                    {
                        richTextBox1.Text = "Address: \n" + BitConverter.ToString(f_address) + "ERROR";
                    });
                    break;
                }
                if (fingerbuff.Skip(i).Take(sequence.Length).SequenceEqual(sequence))
                {
                    i += 8;
                    counter = 0;
                    continue;
                }
                if (counter < 128 && j < fingerhex.Length)
                {
                    fingerhex[j] = fingerbuff[i];
                    counter += 1;
                    j += 1;
                }
            }
            byte[] finger256 = NibblesToBytes(fingerhex);
            Bitmap bmp = ConvertByteArrayToBitmap(finger256, 256, 288);
            pictureBox1.Image = bmp;
            this.Invoke((MethodInvoker)delegate ()
            {
                richTextBox1.Text = "Address: \n" + BitConverter.ToString(f_address) + "\nScan selesai\nBERHASIL";
            });
            serialPort1.Close();
            Thread.CurrentThread.Abort();
        }
        static byte[] InvertByteArray(byte[] array)
        {
            byte[] inverted = new byte[array.Length];
            for (int i = 0; i < array.Length; i++)
            {
                inverted[i] = array[array.Length - 1 - i];
            }
            return inverted;
        }

        public byte[] NibblesToBytes(byte[] data)
        {
            byte[] result = new byte[data.Length * 2];
            int i = 0;
            foreach (var bits in data)
            {
                // You may need to reverse these two lines, depending on data format:
                result[i++] = (byte)((bits & 0x0F) << 4);
                result[i++] = (byte)(bits & 0xF0);
            }

            return result;
        }

        private Bitmap ConvertByteArrayToBitmap(byte[] pixelData, int width, int height)
        {
            // Create an empty bitmap with the specified dimensions
            Bitmap bmp = new Bitmap(width, height, PixelFormat.Format8bppIndexed);

            // Set grayscale color palette
            ColorPalette palette = bmp.Palette;
            for (int i = 0; i < 256; i++)
            {
                palette.Entries[i] = Color.FromArgb(i, i, i);
            }
            bmp.Palette = palette;

            // Lock bitmap bits for writing
            BitmapData bmpData = bmp.LockBits(new Rectangle(0, 0, bmp.Width, bmp.Height),
                                              ImageLockMode.WriteOnly, bmp.PixelFormat);

            // Copy byte array data into bitmap with appropriate padding
            int stride = bmpData.Stride;
            byte[] paddedData = new byte[stride * height];

            for (int y = 0; y < height; y++)
            {
                Array.Copy(pixelData, y * width, paddedData, y * stride, width);
            }

            Marshal.Copy(paddedData, 0, bmpData.Scan0, paddedData.Length);
            bmp.UnlockBits(bmpData);

            return bmp;
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            selectedCOM = comboBox1.Items[comboBox1.SelectedIndex].ToString();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                serialPort1.Close();
                serialPort1.PortName = selectedCOM;
                serialPort1.BaudRate = 57600;
                serialPort1.Open();
                new Thread(fingerpinrt_thread).Start();
            }
            catch
            {
                serialPort1.Close();
                richTextBox1.AppendText("Error Opening Serial");
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            comboBox1.Text = "";
            comboBox1.Items.Clear();
            string[] ports = SerialPort.GetPortNames();
            foreach (string port in ports)
            {
                comboBox1.Items.Add(port);
                comboBox1.SelectedItem = port;
            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            serialPort1.Close();
        }
    }
}
