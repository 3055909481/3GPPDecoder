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


#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QStringRef>
#include <QProcess>
#include <QDebug>
#include <QTextCursor>
#include "preferencedialog.h"
#include "tsharkdecoder.h"
#include "umtsrlcdecoder.h"
#include "aboutdialog.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    void initLogger();

private slots:
    void on_pushButtonDecode_clicked();

    void on_radioButtonGsm_toggled(bool checked);

    void on_radioButtonUmts_toggled(bool checked);

    void on_radioButtonLte_toggled(bool checked);

    void on_radioButtonNr_clicked(bool checked);

    void on_radioButtonNet_clicked(bool checked);

    void on_action_Preference_triggered();

    void on_pushButtonClear_clicked();

    void on_action_Exit_triggered();

    void on_action_About_Decoder_triggered();

    void on_pushButtonWireshark_clicked();

    void on_readoutput();
    void on_readerror();

private:  
    void readfile();
    void setDefaultPreference();

private:
    Ui::MainWindow *ui;
    TSharkDecoder* _pTSharkDecoder;
    UmtsRlcDecoder* _pUmtsRlcDecoder;
    PreferenceDialog* _pPreferenceDialog;
    AboutDialog* _pAboutDialog;

    QProcess* _cmd;
};

#endif // MAINWINDOW_H
