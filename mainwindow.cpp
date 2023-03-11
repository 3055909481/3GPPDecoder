/* This file is part of 3GPP Decoder project.
 * Copyright (C) 2015  Prashant Panigrahi prashant@3glteinfo.com
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <QDir>
#include "lib/include/QsLog.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
//    setWindowFlags(Qt::Window | Qt::WindowMinimizeButtonHint | Qt::WindowCloseButtonHint);
    ui->radioButtonNr->setChecked(true);
    on_radioButtonNr_clicked(true);

    _cmd = new QProcess();
    _cmd->setStandardOutputFile("decode_output_temp.txt");

    _pTSharkDecoder = new TSharkDecoder(_cmd);
    _pUmtsRlcDecoder = new UmtsRlcDecoder();
    _pPreferenceDialog = new PreferenceDialog();
    _pAboutDialog = new AboutDialog();

    initLogger();

        
//    connect(_cmd , SIGNAL(readyReadStandardOutput()) , this , SLOT(on_readoutput()));
//    connect(_cmd , SIGNAL(readyReadStandardError()) , this , SLOT(on_readerror()));
}

MainWindow::~MainWindow()
{
    if(nullptr != _cmd)
    {
      _cmd->close();
      _cmd->waitForFinished();
      delete _cmd;
    }

    if(nullptr != _pTSharkDecoder)
    {
        delete _pTSharkDecoder;
    }
    if(nullptr != _pUmtsRlcDecoder)
    {
        delete _pUmtsRlcDecoder;
    }
    if(nullptr != _pPreferenceDialog)
    {
        delete _pPreferenceDialog;
    }
    if(nullptr != _pAboutDialog)
    {
        delete _pAboutDialog;
    }

    QsLogging::Logger::destroyInstance();

    delete ui;
}

void MainWindow::initLogger()
{
    // 初始化日志机制
    QsLogging::Logger& logger = QsLogging::Logger::instance();
    logger.setLoggingLevel(QsLogging::TraceLevel);

    // 添加文件为目的地
    const QString sLogPath(QDir(QApplication::applicationDirPath()).filePath("log.txt"));
    QsLogging::DestinationPtr fileDestination(QsLogging::DestinationFactory::MakeFileDestination(
      sLogPath, QsLogging::DisableLogRotation, QsLogging::MaxSizeBytes(512*1024), QsLogging::MaxOldLogCount(5)));
    logger.addDestination(fileDestination);
}

void MainWindow::on_pushButtonDecode_clicked()
{
    QString encoded_pdu;
    QString protocol_selected;
    int pdu_length = 0;
    QMessageBox* message_box 	= new QMessageBox();
    //QFile textFile("textfile");
    //QFile pcapFile("pacap");
    encoded_pdu = ui->lineEditData->text();
    protocol_selected = ui->comboBoxProtocol->currentText();
    pdu_length = encoded_pdu.length();
    if(pdu_length == 0)
    {
        message_box->setText("Enter a HEX string to decode");
        message_box->setWindowTitle("Error...");
        message_box->show();
    }
    else
    {
        if(protocol_selected != NULL)
        {
            if(protocol_selected.contains("RLC"))
            {
                encoded_pdu = encoded_pdu.remove(" ");
                encoded_pdu = encoded_pdu.remove("\n");
                if((encoded_pdu.length()%2) != 0)
                {
                    message_box->setText("Check entered data: RLC PDUs are octect aligned.");
                }
                else
                {
                    if(ui->radioButtonUmts->isChecked())
                    {
                        _pUmtsRlcDecoder->start_decoder(encoded_pdu, protocol_selected);
                    }
                }
            }
            else
            {
                //Decode as RRC with TShark
                encoded_pdu = encoded_pdu.remove("\n");
                if(protocol_selected == "NAS")
                {
                    protocol_selected = "gsm_a_dtap";
                }
                _pTSharkDecoder->startDecoder(encoded_pdu, protocol_selected);
            }
            readfile();
        }
    }
}

void MainWindow::readfile(){
    QString filename = "decode_output_temp.txt";
    QFile file(filename);
    if(!file.exists()){
        QLOG_DEBUG() << "No files found "<<filename;
    }else{
        QLOG_DEBUG() << filename<<" File read sucess...";
    }
//    QString line;
    ui->textEditDecoded->clear();
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)){
        QTextStream stream(&file);
        while (!stream.atEnd()){
//            line = stream.readLine();
//            ui->textEditDecoded->setText(ui->textEditDecoded->toPlainText()+line+"\n");
//            QLOG_DEBUG() << "linea: "<<line;
            ui->textEditDecoded->append(stream.readLine());
            ui->textEditDecoded->moveCursor(QTextCursor::Up);
        }
    }
    //file.resize(0);
    file.close();

    //system("del decode_output_temp.txt");
}

void MainWindow::on_radioButtonGsm_toggled(bool checked)
{
    if(checked)
    {
        ui->comboBoxProtocol->clear();
         QStringList strProtocols;
         strProtocols.append("GAN.TCP");
         strProtocols.append("GAN.UDP");
         strProtocols.append("LLC");
         strProtocols.append("NAS");
         strProtocols.append("RR");
         strProtocols.append("RR_dl_with_pseudolength");
         strProtocols.append("RR_ul_with_pseudolength");
         strProtocols.append("SNDCP");
         strProtocols.append("SNDCPXID");
         ui->comboBoxProtocol->addItems(strProtocols);

        /*lookup_dissector_element_t gsm_dissector_lookup_table[] = {
         * {"GAN.TCP","umatcp","Rel 6"},
         * {"GAN.UDP","umaudp","Rel 6"},
         * {"LLC","llcgprs","Rel 6"},
         * {"NAS","gsm_a_dtap","Rel 6"},
         * {"RR","gsm_a_dtap","Rel 6"},
         * {"RR_dl_with_pseudolength","gsm_a_ccch","Rel 6"},
         * {"RR_ul_with_pseudolength","gsm_a_sacch","Rel 6"},
         * {"SNDCP","sndcp","Rel 6"},
         * {"SNDCPXID","sndcpxid","Rel 6"}};
         */
    }
}

void MainWindow::on_radioButtonUmts_toggled(bool checked)
{
    if(checked)
    {
        ui->comboBoxProtocol->clear();
        QStringList strProtocols;
        strProtocols.append("RLC-AM");
        strProtocols.append("RLC-UM");
        strProtocols.append("NAS");
        strProtocols.append("RRC.BCCH.BCH");
        strProtocols.append("RRC.BCCH.FACH");
        strProtocols.append("RRC.DL.CCCH");
        strProtocols.append("RRC.DL.DCCH");
        strProtocols.append("RRC.DL.SHCCH");
        strProtocols.append("RRC.MCCH");
        strProtocols.append("RRC.MSCH");
        strProtocols.append("RRC.PCCH");
        strProtocols.append("RRC.SI.MIB");
        strProtocols.append("RRC.SI.SB1");
        strProtocols.append("RRC.SI.SB2");
        strProtocols.append("RRC.SI.SIB1");
        strProtocols.append("RRC.SI.SIB10");
        strProtocols.append("RRC.SI.SIB11");
        strProtocols.append("RRC.SI.SIB11bis");
        strProtocols.append("RRC.SI.SIB12");
        strProtocols.append("RRC.SI.SIB13");
        strProtocols.append("RRC.SI.SIB13-1");
        strProtocols.append("RRC.SI.SIB13-2");
        strProtocols.append("RRC.SI.SIB13-3");
        strProtocols.append("RRC.SI.SIB13-4");
        strProtocols.append("RRC.SI.SIB14");
        strProtocols.append("RRC.SI.SIB15");
        strProtocols.append("RRC.SI.SIB15bis");
        strProtocols.append("RRC.SI.SIB15-1");
        strProtocols.append("RRC.SI.SIB15-1bis");
        strProtocols.append("RRC.SI.SIB15-2");
        strProtocols.append("RRC.SI.SIB15-2bis");
        strProtocols.append("RRC.SI.SIB15-3");
        strProtocols.append("RRC.SI.SIB15-3bis");
        strProtocols.append("RRC.SI.SIB15-4");
        strProtocols.append("RRC.SI.SIB15-5");
        strProtocols.append("RRC.SI.SIB15-6");
        strProtocols.append("RRC.SI.SIB15-7");
        strProtocols.append("RRC.SI.SIB15-8");
        strProtocols.append("RRC.SI.SIB18");
        strProtocols.append("RRC.SI.SIB17");
        strProtocols.append("RRC.SI.SIB18");
        strProtocols.append("RRC.SI.SIB2");
        strProtocols.append("RRC.SI.SIB3");
        strProtocols.append("RRC.SI.SIB4");
        strProtocols.append("RRC.SI.SIB5");
        strProtocols.append("RRC.SI.SIB5bis");
        strProtocols.append("RRC.SI.SIB6");
        strProtocols.append("RRC.SI.SIB7");
        strProtocols.append("RRC.SI.SIB8");
        strProtocols.append("RRC.SI.SIB9");
        strProtocols.append("RRC.UL.CCCH");
        strProtocols.append("RRC.UL.DCCH");
        strProtocols.append("RRC.UL.SHCCH");
        ui->comboBoxProtocol->addItems(strProtocols);
    }

    /*
     * lookup_dissector_element_t wcdma_dissector_lookup_table[] = {
     * {"NAS","gsm_a_dtap","Rel 6"},
     * {"RRC.BCCH.BCH","rrc.bcch.bch","Rel 8"},
     * {"RRC.BCCH.FACH","rrc.bcch.fach","Rel 8"},
     * {"RRC.DL.CCCH","rrc.dl.ccch","Rel 8"},
     * {"RRC.DL.DCCH","rrc.dl.dcch","Rel 8"},
     * {"RRC.DL.SHCCH","rrc.dl.shcch","Rel 8"},
     * {"RRC.MCCH","rrc.mcch","Rel 8"},
     * {"RRC.MSCH","rrc.msch","Rel 8"},
     * {"RRC.PCCH","rrc.pcch","Rel 8"},
     * {"RRC.SI.MIB","rrc.si.mib","Rel 8"},
     * {"RRC.SI.SB1","rrc.sb1","Rel 8"},
     * {"RRC.SI.SB2","rrc.sb2","Rel 8"},
     * {"RRC.SI.SIB1","rrc.si.sib1","Rel 8"},
     * {"RRC.SI.SIB10","rrc.si.sib10","Rel 8"},
     * {"RRC.SI.SIB11","rrc.si.sib11","Rel 8"},
     * {"RRC.SI.SIB11bis","rrc.si.sib11bis","Rel 8"},
     * {"RRC.SI.SIB12","rrc.si.sib12","Rel 8"},
     * {"RRC.SI.SIB13","rrc.si.sib13","Rel 8"},
     * {"RRC.SI.SIB13-1","rrc.si.sib13-1","Rel 8"},
     * {"RRC.SI.SIB13-2","rrc.si.sib13-2","Rel 8"},
     * {"RRC.SI.SIB13-3","rrc.si.sib13-3","Rel 8"},
     * {"RRC.SI.SIB13-4","rrc.si.sib13-4","Rel 8"},
     * {"RRC.SI.SIB14","rrc.si.sib14","Rel 8"},
     * {"RRC.SI.SIB15","rrc.si.sib15","Rel 8"},
     * {"RRC.SI.SIB15bis","rrc.si.sib15bis","Rel 8"},
     * {"RRC.SI.SIB15-1","rrc.si.sib15-1","Rel 8"},
     * {"RRC.SI.SIB15-1bis","rrc.si.sib15-1bis","Rel 8"},
     * {"RRC.SI.SIB15-2","rrc.si.sib15-2","Rel 8"},
     * {"RRC.SI.SIB15-2bis","rrc.si.sib15-2bis","Rel 8"},
     * {"RRC.SI.SIB15-3","rrc.si.sib15-3","Rel 8"},
     * {"RRC.SI.SIB15-3bis","rrc.si.sib15-3bis","Rel 8"},
     * {"RRC.SI.SIB15-4","rrc.si.sib15-4","Rel 8"},
     * {"RRC.SI.SIB15-5","rrc.si.sib15-5","Rel 8"},
     * {"RRC.SI.SIB15-6","rrc.si.sib15-6","Rel 8"},
     * {"RRC.SI.SIB15-7","rrc.si.sib15-7","Rel 8"},
     * {"RRC.SI.SIB15-8","rrc.si.sib15-8","Rel 8"},
     * {"RRC.SI.SIB18","rrc.si.sib18","Rel 8"},
     * {"RRC.SI.SIB17","rrc.si.sib17","Rel 8"},
     * {"RRC.SI.SIB18","rrc.si.sib18","Rel 8"},
     * {"RRC.SI.SIB2","rrc.si.sib2","Rel 8"},
     * {"RRC.SI.SIB3","rrc.si.sib3","Rel 8"},
     * {"RRC.SI.SIB4","rrc.si.sib4","Rel 8"},
     * {"RRC.SI.SIB5","rrc.si.sib5","Rel 8"},
     * {"RRC.SI.SIB5bis","rrc.si.sib5bis","Rel 8"},
     * {"RRC.SI.SIB6","rrc.si.sib6","Rel 8"},
     * {"RRC.SI.SIB7","rrc.si.sib7","Rel 8"},
     * {"RRC.SI.SIB8","rrc.si.sib8","Rel 8"},
     * {"RRC.SI.SIB9","rrc.si.sib9","Rel 8"},
     * {"RRC.UL.CCCH","rrc.ul.ccch","Rel 8"},
     * {"RRC.UL.DCCH","rrc.ul.dcch","Rel 8"},
     * {"RRC.UL.SHCCH","rrc.ul.shcch","Rel 8"}
};
*/

}


void MainWindow::on_radioButtonLte_toggled(bool checked)
{
    if(checked)
    {
        ui->comboBoxProtocol->clear();
        QStringList strProtocols;
        strProtocols.append("LTE-RRC.BCCH.BCH");
        strProtocols.append("LTE-RRC.BCCH.DL.SCH");
        strProtocols.append("LTE-RRC.DL.CCCH");
        strProtocols.append("LTE-RRC.DL.DCCH");
        strProtocols.append("LTE-RRC.PCCH");
        strProtocols.append("LTE-RRC.UL.CCCH");
        strProtocols.append("LTE-RRC.UL.DCCH");
        strProtocols.append("NAS-EPS");
        ui->comboBoxProtocol->addItems(strProtocols);

        /*
         * Supported protocols for LTE RRC
         * {"LTE-RRC.BCCH.BCH","lte-rrc.bcch.bch","Rel 8"},
         * {"LTE-RRC.BCCH.DL.SCH","lte-rrc.bcch.dl.sch","Rel 8"},
         * {"LTE-RRC.DL.CCCH","lte-rrc.dl.ccch","Rel 8"},
         * {"LTE-RRC.DL.DCCH","lte-rrc.dl.dcch","Rel 8"},
         * {"LTE-RRC.PCCH","lte-rrc.pcch","Rel 8"},
         * {"LTE-RRC.UL.CCCH","lte-rrc.ul.ccch","Rel 8"},
         * {"LTE-RRC.UL.DCCH","lte-rrc.ul.dcch","Rel 8"},
         * {"NAS-EPS","nas-eps","Rel 8"}*/
    }
}

void MainWindow::on_radioButtonNr_clicked(bool checked)
{
    if(checked)
    {
        ui->comboBoxProtocol->clear();
        QStringList strProtocols;
        strProtocols.append("NR-RRC.BCCH.BCH");
        strProtocols.append("NR-RRC.BCCH.DL.SCH");
        strProtocols.append("NR-RRC.DL.CCCH");
        strProtocols.append("NR-RRC.DL.DCCH");
        strProtocols.append("NR-RRC.PCCH");
        strProtocols.append("NR-RRC.UL.CCCH");
        strProtocols.append("NR-RRC.UL.DCCH");
        ui->comboBoxProtocol->addItems(strProtocols);

    }
}

void MainWindow::on_radioButtonNet_clicked(bool checked)
{
    if(checked)
    {
        ui->comboBoxProtocol->clear();
        QStringList strProtocols;
        strProtocols.append("S1AP");
        strProtocols.append("X2AP");
        strProtocols.append("NGAP");
        strProtocols.append("XNAP");
        strProtocols.append("F1AP");
        strProtocols.append("E1AP");
        ui->comboBoxProtocol->addItems(strProtocols);
    }
}

void MainWindow::on_action_Preference_triggered()
{
    _pPreferenceDialog->setModal(true);
    _pPreferenceDialog->exec();
}

void MainWindow::on_pushButtonClear_clicked()
{
    ui->textEditDecoded->clear();
    ui->lineEditData->clear();
}

void MainWindow::on_action_Exit_triggered()
{
    QApplication::quit();
}

void MainWindow::on_action_About_Decoder_triggered()
{
    _pAboutDialog->setModal(true);
    _pAboutDialog->exec();
}

void MainWindow::on_pushButtonWireshark_clicked()
{
    QString protocol_selected;
    protocol_selected = ui->comboBoxProtocol->currentText();
    if(protocol_selected == "NAS")
    {
        protocol_selected = "gsm_a_dtap";
    }

    _pTSharkDecoder->startDecoderWithWireshark(protocol_selected);
}

void MainWindow::on_readoutput()
{
    QLOG_DEBUG() << _cmd->readAllStandardOutput().data();
    QFile file("decode_output_temp.txt");
    file.open(QIODevice::WriteOnly | QIODevice::Text);
    file.write(_cmd->readAllStandardOutput().data());
    file.close();
}

void MainWindow::on_readerror()
{
    QFile file("debug.log");
    file.open(QIODevice::WriteOnly | QIODevice::Text);
    file.write(_cmd->readAllStandardError().data());
    file.close();
}
