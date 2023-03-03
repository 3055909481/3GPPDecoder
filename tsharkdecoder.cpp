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

#include <windows.h>
#include <QDir>
#include <QApplication>
#include "lib/include/QsLog.h"
#include "tsharkdecoder.h"

TSharkDecoder::TSharkDecoder(QProcess* cmd)
{
    _cmd = cmd;
//    _cmd = new QProcess();
//    connect(_cmd , SIGNAL(readyReadStandardOutput()) , this , SLOT(on_readoutput()));
//    connect(_cmd , SIGNAL(readyReadStandardError()) , this , SLOT(on_readerror()));
}

TSharkDecoder::~TSharkDecoder()
{

}

/* Decoding starts here
 */

void TSharkDecoder::startDecoder(QString strEncodedData, QString strProtocol)
{
    QLOG_DEBUG() << "startDecoder, Protocol:" << strProtocol;
    QString strData;
    QString strTsharkPath;
    /*格式化码流*/
    strData = preformatData(strEncodedData);
    strTsharkPath = getTsharkPath();
    strTsharkPath.replace(" ","\" \"");
    QLOG_DEBUG() << strTsharkPath;
    format_file_for_text2pcap(strData);
    /*码流转换为pcap文件*/
    call_text2pacp(strTsharkPath);
    /*接码*/
    call_tshark(strTsharkPath, strProtocol);
    clean_output();
}

void TSharkDecoder::startDecoderWithWireshark(QString strProtocol)
{
    QString strTsharkPath;
    strTsharkPath = getTsharkPath();
    strTsharkPath.replace(" ","\" \"");
    call_tsharkWithWireshark(strTsharkPath, strProtocol);
}

/* Make the incoming packets in HEX format.
 * The packets are encoded in this format:
 * ab - ab
 * a - 0a
 * abcd - ab cd
 */

QString TSharkDecoder::preformatData(QString strEncodedData){

    QString strReturnData;
    QStringList strListData;

    strListData = strEncodedData.split(" ");
    for(int i = 0; i < strListData.length(); i++ )
    {
        if(strListData[i].length() == 2)
        {
            strReturnData.append(" ");
            strReturnData.append(strListData[i]);
        }
        else if(strListData[i].length() == 1)
        {
            strReturnData.append(" 0");
            strReturnData.append(strListData[i]);
        }
        else if(strListData[i].length() > 2)
        {
            for(int j = 0; j < strListData[i].length(); j = j+2)
            {
                QStringRef strTempData = strListData[i].midRef(j, 2);
                strReturnData.append(" ");
                strReturnData.append(strTempData);
            }

        }
    }
    return strReturnData;
}


/* Get the tshark path on Windows.
 * No support for Windows XP at this moment
 */

QString TSharkDecoder::getTsharkPath()
{
    QString strWiresharkLoc;
    strWiresharkLoc = "C:\\Progra~1\\Wireshark\\";
    QFile wiresharkpath("config.txt");
    if(!wiresharkpath.exists())
    {
        return strWiresharkLoc;
    }
    else
    {
        if (wiresharkpath.open(QIODevice::ReadOnly | QIODevice::Text)){
            QTextStream stream(&wiresharkpath);
            QString strLine;
            while (!stream.atEnd()){
                strLine = stream.readLine();
                if(strLine.contains("wireshark:"))
                {
                    strWiresharkLoc = strLine.remove(0,10);
                    if(strWiresharkLoc.contains("86"))
                    {
                        strWiresharkLoc = "C:\\Progra~2\\Wireshark\\";
                    }
                }
            }
        }
    }
    return strWiresharkLoc;
}

/*Create a Textfile which text2pcap can understand.
 * 0000 are added to the beginning of the HEX data
 * to make it text2pacp type
*/

void TSharkDecoder::format_file_for_text2pcap(QString strData)
{
    QLOG_DEBUG() << "start format_file_for_text2pcapformat_file_for_text2pcap";
    QFile textFile("textdata.txt");
    if (textFile.open(QIODevice::ReadWrite)) {
        QTextStream stream(&textFile);
        stream << "0000";
        stream <<strData;
        QLOG_DEBUG() << "data:\n" << strData;
    }
}

/* Make a PCAP file from the textdata.
 * Function calls text2pack.exe from wireshark folder.
 */

void TSharkDecoder::call_text2pacp(QString strTsharkPath)
{
    QLOG_DEBUG() << "start call_text2pacp";
    QStringList arguments;
    arguments << "-q" << "-l" << "147" << "textdata.txt" << "decode_temp.pcap";
    _cmd->start(strTsharkPath + "text2pcap.exe", arguments);
    _cmd->waitForStarted();
    _cmd->waitForFinished();
    _cmd->close();
}

/* Call Tshark to decode the PCAP file.
 * RRC messages are decoded directly
 * NAS messages embeded are also parsed by Tshark.
 */

void TSharkDecoder::call_tshark(QString strTsharkPath, QString strProtocol)
{
    QLOG_DEBUG() << "start call_tshark";
    QString arg;
    arg = arg.append("uat:user_dlts:\"User 0 (DLT=147)\",\"");
    arg = arg.append(strProtocol);
    arg = arg.append("\",\"0\",\"\",\"0\",\"\"");

    QStringList arguments;
    arguments << "-o" << arg << "-r" << "decode_temp.pcap" << "-V";
    _cmd->start(strTsharkPath+"tshark.exe", arguments);
    _cmd->waitForStarted();
    _cmd->waitForFinished();
    _cmd->close();
}

void TSharkDecoder::call_tsharkWithWireshark(QString strTsharkPath, QString strProtocol)
{
    QString arg;
    arg = arg.append("uat:user_dlts:\"User 0 (DLT=147)\",\"");
    arg = arg.append(strProtocol);
    arg = arg.append("\",\"0\",\"\",\"0\",\"\"");
    QStringList arguments;
    arguments << "-o" << arg << "-r" << "decode_temp.pcap";
    _cmd->startDetached(strTsharkPath+"Wireshark.exe", arguments);
    _cmd->waitForStarted();
    _cmd->waitForFinished();
    _cmd->close();
}

/* After decode the first 15 lines are useless data for us.
 * These lines can be removed for a clean presentation
 */

void TSharkDecoder::clean_output()
{
    QFile f("decode_output_temp.txt");
    if(f.open(QIODevice::ReadWrite | QIODevice::Text))
    {
        QString s;
        QTextStream t(&f);
        int i = 0;
        while(!t.atEnd())
        {
            QString line = t.readLine();
            if(i>=15)
                s.append(line + "\n");
            i++;
        }
        f.resize(0);
        t << s;
        f.close();
    }
}

//void TSharkDecoder::on_readoutput()
//{
//    QLOG_DEBUG() << _cmd->readAllStandardOutput().data();
//    QFile file("decode_output_temp.txt");
//    file.open(QIODevice::WriteOnly | QIODevice::Text);
//    file.write(_cmd->readAllStandardOutput().data());
//    file.close();
//}

//void TSharkDecoder::on_readerror()
//{
//    QFile file("debug.log");
//    file.open(QIODevice::WriteOnly | QIODevice::Text);
//    file.write(_cmd->readAllStandardError().data());
//    file.close();
//}
