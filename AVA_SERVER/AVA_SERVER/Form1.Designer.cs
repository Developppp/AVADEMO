﻿
namespace AVA_SERVER
{
    partial class AVASERVER
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            this.ServerPort = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.StartServer = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // ServerPort
            // 
            this.ServerPort.Location = new System.Drawing.Point(89, 14);
            this.ServerPort.Multiline = true;
            this.ServerPort.Name = "ServerPort";
            this.ServerPort.Size = new System.Drawing.Size(74, 17);
            this.ServerPort.TabIndex = 0;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(15, 17);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(71, 12);
            this.label1.TabIndex = 1;
            this.label1.Text = "ServerPort:";
            // 
            // StartServer
            // 
            this.StartServer.Location = new System.Drawing.Point(169, 13);
            this.StartServer.Name = "StartServer";
            this.StartServer.Size = new System.Drawing.Size(75, 19);
            this.StartServer.TabIndex = 2;
            this.StartServer.Text = "Start";
            this.StartServer.UseVisualStyleBackColor = true;
            this.StartServer.Click += new System.EventHandler(this.StartServer_Click);
            // 
            // AVASERVER
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 12F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.StartServer);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.ServerPort);
            this.Name = "AVASERVER";
            this.Text = "AVASERVER";
            this.Load += new System.EventHandler(this.AVASERVER_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox ServerPort;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button StartServer;
    }
}

