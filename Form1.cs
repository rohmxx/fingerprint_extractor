/*
 * Author: rohmxx
 * Date: 2024-11-07
 * Description: Adafruit Fingerprint Address Password Checker and Functionality Test.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO.Ports;
using System.Threading;

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
        int counter = 0;
        bool status = true;

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

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            selectedCOM = comboBox1.Items[comboBox1.SelectedIndex].ToString();
        }

        bool check_bytes(byte[] array1, byte [] array2, int size)
        {
            bool areEqual = true;
            for (int i = 0; i < size; i++)
            {
                if (array1[i] != array2[i])
                {
                    areEqual = false;
                    break;
                }
            }
            return areEqual;
        }

        void fingerpinrt_thread()
        {
            try
            {
                byte[] read_buffer = new byte[12];
                read_buffer[9] = 0xFF;
                int totalLength = start_code.Length + f_address.Length + data_type.Length + wire_len.Length + f_password.Length + data_sum.Length;
                byte[] send_buffer = new byte[totalLength];
                do
                {
                    data_sum[1] = 0x1B;
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
                    {
                        serialPort1.Read(read_buffer, 0, 12);
                    }
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
                    Thread.Sleep(500);
                }
                while (!(read_buffer[9] == 0x00));
                read_buffer[9] = 0xFF;
                UInt16 step_finger = 1;
                UInt16 counter = 0;
                bool done = false;
                while (!done)
                {
                    //getim EF 01 FF FF FF FF 01 00 03 01 00 05
                    byte[] getimage = { 0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x03, 0x01, 0x00, 0x05 };
                    //image EF 01 FF FF FF FF 01 00 04 02 01 00 08
                    byte[] image2tz = { 0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x04, 0x02, 0x01, 0x00, 0x08 };
                    for (int i = 0; i < 4; i++)
                    {
                        getimage[i + 2] = f_address[i];
                        image2tz[i + 2] = f_address[i];
                    }
                    switch (step_finger)
                    {
                        case 1:
                            serialPort1.Write(getimage, 0, getimage.Length);
                            Thread.Sleep(300);
                            if (serialPort1.BytesToRead >= 12) { serialPort1.Read(read_buffer, 0, 12); }
                            this.Invoke((MethodInvoker)delegate ()
                            {
                                richTextBox1.Text = "Tempelkan Jari";
                            });
                            if (read_buffer[9] == 0x00 && read_buffer[11] == 0x0A)
                            {
                                counter += 1;
                                read_buffer[9] = 0xFF;
                                if (counter > 2)
                                {
                                    step_finger = 2;
                                }
                            }
                            else
                            {
                                counter = 0;
                            }
                            break;
                        case 2:
                            serialPort1.Write(image2tz, 0, image2tz.Length);
                            Thread.Sleep(1000);
                            if (serialPort1.BytesToRead >= 12) { serialPort1.Read(read_buffer, 0, 12); }
                            this.Invoke((MethodInvoker)delegate ()
                            {
                                richTextBox1.Text = "Tempelkan Jari";
                            });
                            if (read_buffer[9] == 0x00)
                            {
                                step_finger = 3;
                            }
                            else
                            {
                                step_finger = 1;
                            }
                            break;
                        case 3:
                            if (serialPort1.BytesToRead >= 12) { serialPort1.Read(read_buffer, 0, 12); }
                            this.Invoke((MethodInvoker)delegate ()
                            {
                                richTextBox1.Text = "Berhasil";
                            });
                            done = true;
                            //serialPort1.Write(getimage, 0, getimage.Length);
                            //Thread.Sleep(300);
                            //if (serialPort1.BytesToRead >= 12) { serialPort1.Read(read_buffer, 0, 12); }
                            //this.Invoke((MethodInvoker)delegate ()
                            //{
                            //    richTextBox1.Text = "Tempelkan Jari";
                            //});
                            //if (read_buffer[9] == 0x00 && read_buffer[11] == 0x0A)
                            //{
                            //    read_buffer[9] = 0xFF;
                            //    step_finger = 4;
                            //}
                            break;
                        default:
                            this.Invoke((MethodInvoker)delegate ()
                            {
                                richTextBox1.Text = "Gagal";
                            });
                            done = true;
                            break;
                    }
                }
            }
            catch
            {
                serialPort1.Close();
            }
            serialPort1.Close();
            Thread.CurrentThread.Abort();
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
                status = false;
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
