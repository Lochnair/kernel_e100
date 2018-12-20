pipeline {
    agent {
        docker { image 'lochnair/octeon-buildenv:latest' }
    }

    stages {
        stage('Clean') {
            steps {
               sh 'git reset --hard'
               sh 'git clean -fX'
            }
        }

        stage('Install dependencies') {
            steps {
                sh 'su-exec root apt-get update'
                sh 'su-exec root apt-get -y install bc bison flex'
            }
        }

        stage('Prepare') {
            steps {
                sh 'make ARCH=mips ubnt_er_e100_defconfig'
            }
        }

        stage('Prepare for out-of-tree builds') {
            steps {
                sh 'make -j5 ARCH=mips CROSS_COMPILE=mips64-octeon-linux- prepare modules_prepare'
                sh 'rm -rf tmp && mkdir tmp'
                sh 'tar --exclude-vcs --exclude=tmp -cf tmp/e100-ksrc.tar .'
                sh 'mv tmp/e100-ksrc.tar e100-ksrc.tar'
            }
        }

        stage('Build') {
            steps {
                sh 'make -j5 ARCH=mips CROSS_COMPILE=mips64-octeon-linux- vmlinux modules'
            }
        }
        
        stage('Archive kernel image') {
            steps {
                sh 'mv -v vmlinux vmlinux.64'
                sh 'tar cvjf e100-kernel.tar.bz2 vmlinux.64'
                archiveArtifacts artifacts: 'e100-kernel.tar.bz2', fingerprint: true, onlyIfSuccessful: true
            }
        }
        
        stage('Archive kernel modules') {
            steps {
                sh 'make ARCH=mips CROSS_COMPILE=mips64-octeon-linux- INSTALL_MOD_PATH=destdir modules_install'
                sh 'tar cvjf e100-modules.tar.bz2 -C destdir .'
                archiveArtifacts artifacts: 'e100-modules.tar.bz2', fingerprint: true, onlyIfSuccessful: true
            }
        }

        stage('Archive build tree') {
            steps {
                sh 'tar -uvf e100-ksrc.tar Module.symvers'
                sh 'bzip2 e100-ksrc.tar'
                archiveArtifacts artifacts: 'e100-ksrc.tar.bz2', fingerprint: true, onlyIfSuccessful: true
            }
        }
    }
}

